// Package simdns provides a battery of loopback UDP DNS servers that simulate
// remote recursive resolvers. It is used to benchmark DNS resolvers (the native
// resolver as well as the massdns binary) without sending any traffic to the
// public internet.
//
// Each simulated resolver models realistic remote conditions: response latency
// with jitter, packet loss, a SERVFAIL rate, and an optional per-resolver QPS
// cap (over-budget queries are dropped, like a throttling public resolver). The
// answered/NXDOMAIN decision is deterministic per name, so the workload is
// stable and reproducible across runs and across engines.
package simdns

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Config describes the simulated behaviour of one remote resolver.
type Config struct {
	BaseLatency  time.Duration // minimum response delay
	Jitter       time.Duration // additional uniform-random delay on top of base
	LossRate     float64       // fraction of queries silently dropped (0..1)
	ServfailRate float64       // fraction of queries answered with SERVFAIL (0..1)
	QPSPerServer int           // per-resolver rate cap; over-budget queries are dropped (0 = unlimited)
	HitPercent   int           // fraction of names that return an A record
	// HijackRate models a misbehaving recursive resolver that returns NXDOMAIN
	// for a name that actually exists (e.g. rate-limit-induced false negatives
	// or NXDOMAIN hijacking). This is the massdns #117 failure mode: the stub
	// resolver believes the NXDOMAIN (terminal, not retried) and misses the
	// name. Fraction 0..1 of otherwise-hitting queries answered NXDOMAIN.
	HijackRate float64
}

// Stats aggregates what the battery actually did, for sanity reporting.
type Stats struct {
	Queries     atomic.Int64
	Answered    atomic.Int64
	Dropped     atomic.Int64
	Servfail    atomic.Int64
	RateLimited atomic.Int64
	Hijacked    atomic.Int64 // existing names falsely answered NXDOMAIN
}

// tokenBucket is a tiny non-blocking rate limiter used to model a resolver that
// rate-limits and drops excess traffic.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	refill   float64 // tokens per second
	lastFill time.Time
}

func newTokenBucket(qps int) *tokenBucket {
	if qps <= 0 {
		return nil
	}
	return &tokenBucket{
		tokens:   float64(qps),
		max:      float64(qps),
		refill:   float64(qps),
		lastFill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.lastFill).Seconds() * b.refill
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastFill = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// resolver is a single loopback UDP DNS server modelling a remote resolver.
type resolver struct {
	conn    *net.UDPConn
	cfg     Config
	stats   *Stats
	bucket  *tokenBucket
	closeCh chan struct{}
	wg      sync.WaitGroup
}

// Battery is a running set of simulated resolvers.
type Battery struct {
	Addrs     []string // resolver addresses in host:port form (loopback)
	Stats     *Stats
	resolvers []*resolver
}

// Start launches n simulated resolvers on ephemeral 127.0.0.1 ports.
func Start(n int, cfg Config) (*Battery, error) {
	b := &Battery{Stats: &Stats{}}

	for i := 0; i < n; i++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			b.Stop()
			return nil, err
		}
		_ = conn.SetReadBuffer(8 * 1024 * 1024)
		_ = conn.SetWriteBuffer(8 * 1024 * 1024)
		r := &resolver{
			conn:    conn,
			cfg:     cfg,
			stats:   b.Stats,
			bucket:  newTokenBucket(cfg.QPSPerServer),
			closeCh: make(chan struct{}),
		}
		b.resolvers = append(b.resolvers, r)
		b.Addrs = append(b.Addrs, conn.LocalAddr().String())
		r.wg.Add(1)
		go r.serve()
	}

	return b, nil
}

// Stop shuts down all simulated resolvers and waits for their goroutines.
func (b *Battery) Stop() {
	for _, r := range b.resolvers {
		select {
		case <-r.closeCh:
		default:
			close(r.closeCh)
		}
		_ = r.conn.Close()
	}
	for _, r := range b.resolvers {
		r.wg.Wait()
	}
}

func (r *resolver) serve() {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.closeCh:
				return
			default:
				continue
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		r.wg.Add(1)
		go r.handle(pkt, addr)
	}
}

func (r *resolver) handle(pkt []byte, addr *net.UDPAddr) {
	defer r.wg.Done()

	r.stats.Queries.Add(1)

	// per-resolver rate cap: drop what we cannot serve, like a throttling
	// public resolver. The client should rotate to another resolver and retry.
	if r.bucket != nil && !r.bucket.allow() {
		r.stats.RateLimited.Add(1)
		return
	}

	// simulate packet loss: silently drop, forcing a retransmit on timeout.
	if r.cfg.LossRate > 0 && rand.Float64() < r.cfg.LossRate {
		r.stats.Dropped.Add(1)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(pkt); err != nil || len(req.Question) == 0 {
		return
	}
	q := req.Question[0]

	// simulate RTT
	delay := r.cfg.BaseLatency
	if r.cfg.Jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(r.cfg.Jitter) + 1))
	}
	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-r.closeCh:
			t.Stop()
			return
		}
	}

	m := new(dns.Msg)
	m.SetReply(req)

	switch {
	case r.cfg.ServfailRate > 0 && rand.Float64() < r.cfg.ServfailRate:
		m.Rcode = dns.RcodeServerFailure
		r.stats.Servfail.Add(1)
	case q.Qtype == dns.TypeA && NameHits(q.Name, r.cfg.HitPercent) && r.cfg.HijackRate > 0 && rand.Float64() < r.cfg.HijackRate:
		// existing name falsely reported as NXDOMAIN (rate-limit/hijack); the
		// stub believes it and produces a false negative.
		m.Rcode = dns.RcodeNameError
		r.stats.Hijacked.Add(1)
	case q.Qtype == dns.TypeA && NameHits(q.Name, r.cfg.HitPercent):
		rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, SyntheticIP(q.Name)))
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	case q.Qtype == dns.TypePTR && NameHits(q.Name, r.cfg.HitPercent):
		rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN PTR %s", q.Name, SyntheticPTR(q.Name)))
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	default:
		m.Rcode = dns.RcodeNameError
	}

	out, err := m.Pack()
	if err != nil {
		return
	}
	if _, err := r.conn.WriteToUDP(out, addr); err == nil {
		r.stats.Answered.Add(1)
	}
}

// NameHits deterministically decides whether a name resolves, so the hit ratio
// is stable across runs and across resolvers (every resolver agrees).
func NameHits(name string, hitPercent int) bool {
	if hitPercent >= 100 {
		return true
	}
	if hitPercent <= 0 {
		return false
	}
	return int(fnv32(name)%100) < hitPercent
}

// SyntheticIP returns a deterministic plausible host address for a name.
func SyntheticIP(name string) string {
	h := fnv32(name)
	last := byte(h%254) + 1 // avoid .0/.255
	return fmt.Sprintf("10.%d.%d.%d", byte(h>>16), byte(h>>8), last)
}

// SyntheticPTR returns a deterministic plausible hostname for a reverse query.
func SyntheticPTR(name string) string {
	return fmt.Sprintf("host-%d.ptr.example.com.", fnv32(name)%100000)
}

func fnv32(s string) uint32 {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}
