// Package resolve implements a high-throughput asynchronous DNS stub
// resolver in pure Go. It is the native replacement for the massdns binary
// previously shelled out to by shuffledns.
//
// Design (mirrors massdns rather than the naive goroutine-per-query model):
//   - a small fixed pool of UDP sockets, each drained by a single reader
//     goroutine, so concurrency is bounded by an in-flight map and NOT by
//     the number of goroutines;
//   - queries are tracked in a per-socket in-flight table keyed by DNS
//     transaction id; responses are correlated back by id + question name;
//   - a timeout wheel retransmits unanswered queries to a different resolver
//     up to a retry budget, and retries REFUSED/SERVFAIL like massdns does;
//   - results stream out through a callback as soon as they arrive (no temp
//     files, no text parsing), which is what gives a low time-to-first-result.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Result is a single resolved answer streamed to the caller.
type Result struct {
	Name     string   // queried hostname (no trailing dot)
	Type     uint16   // dns query type (A, AAAA, ...)
	Rcode    int      // dns response code
	A        []string // A records
	AAAA     []string // AAAA records
	CNAME    []string // CNAME targets
	NS       []string // NS targets
	PTR      []string // PTR targets
	MX       []string // MX exchange hosts
	TXT      []string // TXT strings
	SOA      []string // SOA primary nameservers
	Resolver string   // resolver that answered

	// Msg is the full parsed response message (all sections, TTLs, classes).
	// It is retained so callers (e.g. the output formatter) can render the
	// complete answer faithfully; it may be nil for synthetic results.
	Msg *dns.Msg
	// Timestamp is when the response was accepted as final (wall clock).
	Timestamp time.Time
}

// Options configures the resolver.
type Options struct {
	// Resolvers is the list of recursive resolver addresses (host or host:port).
	Resolvers []string
	// QueryType is the dns record type to request (default dns.TypeA).
	QueryType uint16
	// MaxRetries is the number of times a query is retransmitted (to a
	// rotated resolver) before giving up. Default 3.
	MaxRetries int
	// Timeout is the per-attempt timeout before retransmission. Default 4s.
	Timeout time.Duration
	// Concurrency caps the number of in-flight queries. Default 10000.
	Concurrency int
	// QPS optionally rate-limits outbound queries (0 = unlimited).
	QPS int
	// SocketCount is the number of UDP sockets to spread load across.
	// Default max(8, GOMAXPROCS) so the read path scales across cores.
	SocketCount int
	// Batch selects the datagram batching strategy (sendmmsg/recvmmsg, Linux
	// only, IPv4-only resolver set). See BatchMode. Default BatchDisabled.
	Batch BatchMode
	// BatchSize is the maximum number of datagrams sent/received per syscall
	// when batching is active. Default 64.
	BatchSize int

	// Interval is the timeout-loop scan period (how promptly a lost packet is
	// retransmitted). 0 = derive from Timeout. Mirrors massdns -i/--interval.
	Interval time.Duration

	// NoRecurse sends non-recursive queries (RD=0), useful for cache snooping
	// and probing authoritative servers directly. Mirrors massdns --norecurse.
	NoRecurse bool
	// UDPSize is the EDNS0 advertised UDP payload size. 0 = default (1232),
	// which lets resolvers return larger answers without truncation. A value
	// below 512 disables EDNS0 entirely.
	UDPSize int
	// DisableIPVerification turns off matching a reply's source address against
	// the resolver the query was sent to. Verification is ON by default and
	// guards against off-path answer spoofing (massdns --verify-ip is opt-in;
	// here it is opt-out because we always send to a known address).
	DisableIPVerification bool
	// DisableTCPFallback disables re-querying over TCP when a UDP response has
	// the truncation (TC) bit set. Fallback is ON by default.
	DisableTCPFallback bool
	// Sticky retransmits to the same resolver instead of rotating. Mirrors
	// massdns --sticky.
	Sticky bool
	// RetryRcodes lists the response codes that trigger a retry. When nil the
	// massdns default is used: retry everything except NOERROR and NXDOMAIN.
	RetryRcodes []int

	// ResolverHealth enables per-resolver health scoring: resolvers that time
	// out or error are de-weighted in selection and recover over time.
	ResolverHealth bool
	// AdaptiveConcurrency lets the controller shrink/grow the in-flight cap in
	// response to packet loss (AIMD), preventing resolver/buffer flooding.
	// Requires Batch == BatchAdaptive (the controller drives both).
	AdaptiveConcurrency bool
	// CrossCheck re-queries each positive answer on a second, randomly chosen
	// resolver and drops results the two disagree on (basic poisoning/spam
	// detection). Doubles query volume for names that resolve.
	CrossCheck bool
	// ExtendedInput parses each input line as "name [resolver ...]"; the
	// per-name resolvers are tried (in order) before falling back to the global
	// resolver pool. Mirrors massdns --extended-input.
	ExtendedInput bool
	// Predictable picks resolvers sequentially instead of randomly. Mirrors
	// massdns --predictable (useful for resolver tests).
	Predictable bool
	// BindAddr is an optional local UDP bind address (host, host:port, or :port).
	// Empty means the kernel picks an ephemeral port on all interfaces.
	// Mirrors massdns -b/--bindto.
	BindAddr string
	// ReadBuffer, when > 0, sets SO_RCVBUF on each UDP socket (massdns --rcvbuf).
	// When 0 a large default (8 MiB) is used.
	ReadBuffer int
	// WriteBuffer, when > 0, sets SO_SNDBUF on each UDP socket (massdns --sndbuf).
	WriteBuffer int
	// RandSrcIPv6 is a CIDR prefix used to forge a random IPv6 source address
	// per query (massdns --rand-src-ipv6). Linux-only; requires CAP_NET_RAW.
	// Incompatible with BindAddr.
	RandSrcIPv6 string
	// RandSrcIPv6File loads discrete IPv6 source addresses (one per line) for
	// the same purpose (massdns --rand-src-ipv6-file). Mutually exclusive with
	// RandSrcIPv6.
	RandSrcIPv6File string

	// OnResult is invoked for every final answer (success or definitive
	// failure such as NXDOMAIN). It must be safe for concurrent use.
	OnResult func(Result)
	// OnError is invoked when a query is abandoned after exhausting retries.
	OnError func(name string, err error)
	// OnProgress is invoked periodically (every Interval-ish tick) with a
	// snapshot of resolver statistics, for status reporting. Optional.
	OnProgress func(Stats)

	// Hooks holds optional fine-grained lifecycle callbacks for SDK/observability
	// use. They are independent of OnResult/OnError/OnProgress and may all be
	// left nil. See Hooks.
	Hooks Hooks
}

// Stats is a point-in-time snapshot of resolver activity.
type Stats struct {
	Queries        int64   // distinct names dispatched
	Retransmits    int64   // total retransmissions
	Answered       int64   // final answers delivered (success or definitive)
	InflightDepth  int     // queries currently outstanding
	ConcurrencyCap int     // current adaptive in-flight cap
	LossRate       float64 // most recent interval loss estimate
	RTT            time.Duration
	BatchActive    bool
}

// QueryInfo describes a single query attempt passed to lifecycle hooks.
type QueryInfo struct {
	Name     string // queried hostname (no trailing dot)
	Type     uint16 // dns query type
	Attempt  int    // zero-based attempt number (0 = initial send)
	Resolver string // resolver address this attempt targets
}

// Hooks is a set of optional callbacks for observing the resolver's internals,
// intended for embedding the resolver as an SDK (progress UIs, metrics,
// tracing, custom retry/poisoning telemetry, etc.).
//
// IMPORTANT: hooks fire on hot paths (some per query/response). They must be
// cheap, non-blocking, and safe for concurrent use; offload heavy work to a
// channel or worker. Any hook may be nil. Hooks never alter resolver behaviour
// — they are observation points only.
type Hooks struct {
	// OnQuery fires when a query is first put on the wire (initial send).
	OnQuery func(QueryInfo)
	// OnRetry fires before each retransmission (timeout or bad-rcode driven).
	OnRetry func(QueryInfo)
	// OnResponse fires for every response matched to an in-flight query, before
	// the retry-or-finalize decision, exposing the raw message (read-only).
	OnResponse func(QueryInfo, *dns.Msg)
	// OnTimeout fires when an attempt's deadline expires (before retry/abandon).
	OnTimeout func(QueryInfo)
	// OnTruncated fires when a TC (truncated) response triggers TCP fallback.
	OnTruncated func(QueryInfo)
	// OnCrossCheckFailed fires when cross-resolver verification rejects a result;
	// primary/secondary are the disagreeing A-record sets.
	OnCrossCheckFailed func(name string, primary, secondary []string)
	// OnResolverState fires when a resolver's health crosses the healthy
	// threshold (requires ResolverHealth). healthy is the new state.
	OnResolverState func(resolver string, healthy bool)
}

// fire helpers keep the hot paths branch-cheap when hooks are unset.
func (c *Client) fireQuery(q *query) {
	if c.hooks.OnQuery != nil {
		c.hooks.OnQuery(c.queryInfo(q))
	}
}

func (c *Client) fireRetry(q *query) {
	if c.hooks.OnRetry != nil {
		c.hooks.OnRetry(c.queryInfo(q))
	}
}

func (c *Client) queryInfo(q *query) QueryInfo {
	res := ""
	if q.addr != nil {
		res = q.addr.String()
	}
	return QueryInfo{Name: q.name, Type: c.opts.QueryType, Attempt: q.attempts, Resolver: res}
}

// BatchMode selects how datagram batching (Linux sendmmsg/recvmmsg) is used.
//
// Batching amortizes the per-datagram syscall cost and helps on high-latency /
// bursty links where many packets cluster in time, but it is counterproductive
// on loopback / low-RTT links (tiny batches pay the message-array setup cost
// and add first-response latency). It also makes sends burstier, which can
// worsen loss when a resolver or kernel buffer is already saturated.
type BatchMode int

const (
	// BatchDisabled always uses one datagram per syscall (default). Identical
	// to the resolver's behaviour without any batching support.
	BatchDisabled BatchMode = iota
	// BatchEnabled forces batching on (Linux + IPv4 resolvers only).
	BatchEnabled
	// BatchAdaptive turns batching on/off at runtime based on observed RTT,
	// in-flight depth and packet loss: it engages when the pipeline is deep and
	// latency is high enough to fill batches, and backs off on low-RTT links or
	// when loss climbs (to avoid making sends burstier).
	BatchAdaptive
)

const (
	defaultMaxRetries  = 3
	defaultTimeout     = 4 * time.Second
	defaultConcurrency = 10000
	defaultSocketCount = 8
	defaultBatchSize   = 64
	defaultUDPSize     = 1232 // conservative EDNS0 payload (avoids v4/v6 fragmentation)
	maxTxIDAttempts    = 64

	// adaptive batching controller thresholds (with hysteresis to avoid flapping)
	adaptTick       = 200 * time.Millisecond
	adaptRTTOn      = 3 * time.Millisecond // engage batching above this smoothed RTT
	adaptRTTOff     = 1 * time.Millisecond // disengage below this smoothed RTT
	adaptLossOff    = 0.15                 // disengage when interval loss exceeds this
	minBatchToMMSG  = 4                    // only use sendmmsg for batches at least this big
	adaptDepthRatio = 2                    // need depth >= ratio*batchSize to engage

	// adaptive concurrency (AIMD) thresholds
	concLossHigh = 0.10 // multiplicative decrease above this interval loss
	concLossLow  = 0.02 // additive increase below this interval loss
	concDecrease = 0.75 // cap *= concDecrease on high loss
	concMinRatio = 0.05 // never shrink below this fraction of Concurrency
)

// query holds the in-flight state for a single outstanding name.
type query struct {
	name        string
	fqdn        string
	txid        uint16
	resolverIdx int
	addr        *net.UDPAddr   // resolver this attempt was sent to (for verify + retransmit)
	extra       []*net.UDPAddr // per-name resolvers (extended-input); tried before the pool
	sentAt      time.Time
	deadline    time.Time
	attempts    int
	sock        *socket
}

// batchConn is the subset of ipv4.PacketConn / ipv6.PacketConn used for batched
// I/O. ipv4.Message and ipv6.Message are both aliases of the same underlying
// socket.Message type, so a single interface works for either family.
type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// socket is a UDP socket plus its in-flight table.
type socket struct {
	conn     *net.UDPConn
	rawFD    int  // >=0: Linux SOCK_RAW IPv6 for --rand-src-ipv6; conn is nil
	family   int  // 4, 6, or 0 (dual-stack)
	pc       batchConn // batch (sendmmsg/recvmmsg) wrapper; nil if batching unavailable
	mu       sync.Mutex
	inflight map[uint16]*query
}

// Client is an asynchronous DNS stub resolver.
type Client struct {
	opts          Options
	resolvers     []string
	resolverAddrs []*net.UDPAddr // pre-resolved, shared read-only across goroutines
	sockets       []*socket
	sem           chan struct{} // static in-flight cap (fast path)
	dynSem        *adaptiveSem  // adjustable in-flight cap (AdaptiveConcurrency); nil otherwise
	limiter       *limiter
	pending       sync.WaitGroup
	srcRand       *srcRand
	sockets4      []*socket // IPv4-capable sockets (subset of sockets)
	sockets6      []*socket // IPv6-capable sockets (subset of sockets)

	rd          bool // recursion desired flag for outgoing queries
	udpSize     uint16
	verify      bool // verify reply source address
	tcp         bool // TCP fallback on truncation
	sticky      bool
	predictable bool
	predSeq     atomic.Uint64 // monotonic index for Predictable resolver selection
	extInput    bool          // parse per-name resolvers from input lines
	retryRcode  [16]bool      // retryRcode[rcode] => retransmit on this response code
	sockIdx     atomic.Uint64

	addrCache sync.Map        // string -> *net.UDPAddr (extended-input resolver cache)
	health    *resolverHealth // nil unless ResolverHealth enabled
	hooks     Hooks           // optional lifecycle callbacks

	// precomputed hot-path gates so the common (no-hook) path costs a single
	// bool test instead of per-query nil checks / function calls.
	hasSendHooks bool // OnQuery or OnRetry set
	sampleRTT    bool // RTT sampling needed (adaptive batch/concurrency or OnProgress)

	// batchCapable is true when the batch I/O path is usable (mode != disabled
	// and a single-family resolver set). When true, the dispatch/read loops use
	// the batch-aware path and consult batchActive to decide per operation.
	batchCapable bool
	batchSize    int
	// batchActive is flipped by the adaptive controller (or pinned on/off for
	// the non-adaptive modes); send/read paths read it to choose mmsg vs single.
	batchActive atomic.Bool

	// adaptive metrics (cheap atomics sampled by the controller)
	statQueries    atomic.Int64  // distinct names dispatched (initial sends)
	statRetransmit atomic.Int64  // retransmissions (timeout + servfail/refused retries)
	statAnswered   atomic.Int64  // final answers delivered
	lastRTTNanos   atomic.Int64  // most recent observed round-trip time
	lastLossBits   atomic.Uint64 // most recent interval loss (float64 bits) for stats
}

// New creates a resolver client from the given options.
func New(opts Options) (*Client, error) {
	if len(opts.Resolvers) == 0 {
		return nil, errors.New("no resolvers provided")
	}
	if opts.QueryType == 0 {
		opts.QueryType = dns.TypeA
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = defaultMaxRetries
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.SocketCount <= 0 {
		// scale the socket pool (and thus the number of independent reader
		// goroutines / kernel receive queues) with the available cores.
		opts.SocketCount = defaultSocketCount
		if n := runtime.GOMAXPROCS(0); n > opts.SocketCount {
			opts.SocketCount = n
		}
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}
	if opts.UDPSize == 0 {
		opts.UDPSize = defaultUDPSize
	}

	resolvers := make([]string, 0, len(opts.Resolvers))
	resolverAddrs := make([]*net.UDPAddr, 0, len(opts.Resolvers))
	allIPv4, allIPv6 := true, true
	for _, r := range opts.Resolvers {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		normalized := normalizeResolver(r)
		// pre-resolve once at startup so the hot send() path never parses an
		// address string or allocates a *net.UDPAddr per query/retransmit.
		addr, err := net.ResolveUDPAddr("udp", normalized)
		if err != nil {
			return nil, err
		}
		if addr.IP.To4() == nil {
			allIPv4 = false
		} else {
			allIPv6 = false
		}
		resolvers = append(resolvers, normalized)
		resolverAddrs = append(resolverAddrs, addr)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("no valid resolvers provided")
	}

	c := &Client{
		opts:          opts,
		resolvers:     resolvers,
		resolverAddrs: resolverAddrs,
		batchSize:     opts.BatchSize,
		rd:            !opts.NoRecurse,
		verify:        !opts.DisableIPVerification,
		tcp:           !opts.DisableTCPFallback,
		sticky:        opts.Sticky,
		predictable:   opts.Predictable,
		extInput:      opts.ExtendedInput,
		hooks:         opts.Hooks,
	}
	if opts.UDPSize >= 512 {
		c.udpSize = uint16(opts.UDPSize)
	}
	if opts.RandSrcIPv6 != "" && opts.RandSrcIPv6File != "" {
		return nil, errors.New("--rand-src-ipv6 cannot be used with --rand-src-ipv6-file")
	}
	if (opts.RandSrcIPv6 != "" || opts.RandSrcIPv6File != "") && opts.BindAddr != "" {
		return nil, errors.New("--bindto and --rand-src-ipv6 cannot be used together")
	}
	switch {
	case opts.RandSrcIPv6 != "":
		sr, err := newSrcRandFromPrefix(opts.RandSrcIPv6)
		if err != nil {
			return nil, err
		}
		c.srcRand = sr
	case opts.RandSrcIPv6File != "":
		sr, err := newSrcRandFromFile(opts.RandSrcIPv6File)
		if err != nil {
			return nil, err
		}
		c.srcRand = sr
	}
	// Batching uses an ipv4/ipv6 PacketConn, so it requires a single-family
	// resolver set (and a matching udp4/udp6 socket). Mixed sets always use the
	// portable single-datagram path. Raw IPv6 source randomization also disables
	// batching (HDRINCL path is single-datagram only).
	c.batchCapable = opts.Batch != BatchDisabled && (allIPv4 || allIPv6) && c.srcRand == nil

	// precompute hot-path hook/sampling gates (see field docs).
	c.hasSendHooks = opts.Hooks.OnQuery != nil || opts.Hooks.OnRetry != nil
	c.sampleRTT = (c.batchCapable && opts.Batch == BatchAdaptive) ||
		opts.AdaptiveConcurrency || opts.OnProgress != nil

	// retry policy: explicit list, or massdns default (retry all but NOERROR/NXDOMAIN).
	if len(opts.RetryRcodes) > 0 {
		for _, rc := range opts.RetryRcodes {
			if rc >= 0 && rc < len(c.retryRcode) {
				c.retryRcode[rc] = true
			}
		}
	} else {
		for rc := range c.retryRcode {
			c.retryRcode[rc] = true
		}
		c.retryRcode[dns.RcodeSuccess] = false
		c.retryRcode[dns.RcodeNameError] = false
	}

	if opts.ResolverHealth {
		c.health = newResolverHealth(len(resolvers))
	}

	if opts.AdaptiveConcurrency {
		c.dynSem = newAdaptiveSem(opts.Concurrency)
	} else {
		c.sem = make(chan struct{}, opts.Concurrency)
	}

	// BatchEnabled pins batching on; BatchAdaptive starts off and lets the
	// controller engage it when conditions warrant.
	c.batchActive.Store(opts.Batch == BatchEnabled && c.batchCapable)
	if opts.QPS > 0 {
		c.limiter = newLimiter(opts.QPS)
	}

	readBuf := 8 * 1024 * 1024
	if opts.ReadBuffer > 0 {
		readBuf = opts.ReadBuffer
	}

	// --rand-src-ipv6 uses Linux SOCK_RAW + IPV6_HDRINCL (massdns). Requires
	// IPv6 resolvers and CAP_NET_RAW; batching stays off.
	if c.srcRand != nil {
		if !allIPv6 {
			return nil, errors.New("--rand-src-ipv6 requires IPv6 resolvers")
		}
		for i := 0; i < opts.SocketCount; i++ {
			fd, err := openRawUDPv6()
			if err != nil {
				c.closeSockets()
				return nil, err
			}
			_ = setRawRecvBuffer(fd, readBuf)
			if opts.WriteBuffer > 0 {
				_ = setRawSendBuffer(fd, opts.WriteBuffer)
			}
			s := &socket{
				rawFD:    fd,
				family:   6,
				inflight: make(map[uint16]*query),
			}
			c.sockets = append(c.sockets, s)
			c.sockets6 = append(c.sockets6, s)
		}
		return c, nil
	}

	network := "udp"
	family := 0
	switch {
	case c.batchCapable && allIPv4:
		network = "udp4"
		family = 4
	case c.batchCapable && allIPv6:
		network = "udp6"
		family = 6
	}
	var bindAddr *net.UDPAddr
	if opts.BindAddr != "" {
		var err error
		bindAddr, err = net.ResolveUDPAddr(network, normalizeBindAddr(opts.BindAddr))
		if err != nil {
			return nil, fmt.Errorf("bind address: %w", err)
		}
	}
	for i := 0; i < opts.SocketCount; i++ {
		conn, err := net.ListenUDP(network, bindAddr)
		if err != nil {
			c.closeSockets()
			return nil, err
		}
		_ = conn.SetReadBuffer(readBuf)
		if opts.WriteBuffer > 0 {
			_ = conn.SetWriteBuffer(opts.WriteBuffer)
		}
		s := &socket{
			conn:     conn,
			rawFD:    -1,
			family:   family,
			inflight: make(map[uint16]*query),
		}
		if c.batchCapable {
			if allIPv6 {
				s.pc = ipv6.NewPacketConn(conn)
			} else {
				s.pc = ipv4.NewPacketConn(conn)
			}
		}
		c.sockets = append(c.sockets, s)
		switch family {
		case 4:
			c.sockets4 = append(c.sockets4, s)
		case 6:
			c.sockets6 = append(c.sockets6, s)
		default:
			c.sockets4 = append(c.sockets4, s)
			c.sockets6 = append(c.sockets6, s)
		}
	}

	return c, nil
}

// normalizeBindAddr accepts host, host:port, or :port forms used by massdns -b.
func normalizeBindAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ":0"
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	// bare IPv6 needs brackets before appending port
	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() == nil {
			return "[" + ip.String() + "]:0"
		}
		return ip.String() + ":0"
	}
	// hostname without port
	if !strings.Contains(addr, ":") {
		return addr + ":0"
	}
	return addr
}

// Run consumes hostnames from input and resolves them, blocking until input
// is closed and all in-flight queries have completed or the context is
// cancelled. It is safe to call Run only once per Client.
func (c *Client) Run(ctx context.Context, input <-chan string) error {
	if c.limiter != nil {
		c.limiter.start(ctx)
		defer c.limiter.stop()
	}

	readerCtx, cancelReaders := context.WithCancel(ctx)
	defer cancelReaders()

	var readerWg sync.WaitGroup
	for _, s := range c.sockets {
		readerWg.Add(1)
		go func(s *socket) {
			defer readerWg.Done()
			c.readLoop(readerCtx, s)
		}(s)
	}

	timeoutDone := make(chan struct{})
	go func() {
		defer close(timeoutDone)
		c.timeoutLoop(readerCtx)
	}()

	if c.dynSem != nil {
		c.dynSem.watch(readerCtx)
	}

	// the controller drives adaptive batching, adaptive concurrency, and
	// periodic progress reporting; start it if any of those is requested.
	if (c.batchCapable && c.opts.Batch == BatchAdaptive) || c.dynSem != nil || c.opts.OnProgress != nil {
		go c.controllerLoop(readerCtx)
	}

	if c.batchCapable {
		c.dispatchBatched(ctx, input)
	} else {
		c.dispatchSingle(ctx, input)
	}

	// Wait for outstanding queries to drain (success, NXDOMAIN, or retry
	// exhaustion all release the pending counter).
	waitDone := make(chan struct{})
	go func() {
		c.pending.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-ctx.Done():
	}

	// stop the timeout loop first so it cannot issue further retransmits, then
	// close the sockets to immediately unblock the reader goroutines.
	cancelReaders()
	<-timeoutDone
	c.closeSockets()
	readerWg.Wait()
	return ctx.Err()
}

// Close releases the underlying sockets. It must be called when the client is
// no longer needed (Run does not close sockets so the client can be reused for
// diagnostics, but typical callers Close after Run).
func (c *Client) Close() {
	c.closeSockets()
}

func (c *Client) closeSockets() {
	for _, s := range c.sockets {
		if s == nil {
			continue
		}
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
		if s.rawFD >= 0 {
			closeRawFD(s.rawFD)
			s.rawFD = -1
		}
	}
}

// pickSocket selects a UDP/raw socket that can reach addr's address family.
func (c *Client) pickSocket(addr *net.UDPAddr) *socket {
	pool := c.sockets
	if addr != nil {
		if addr.IP.To4() == nil {
			if len(c.sockets6) > 0 {
				pool = c.sockets6
			}
		} else if len(c.sockets4) > 0 {
			pool = c.sockets4
		}
	}
	if len(pool) == 0 {
		return nil
	}
	return pool[int(c.sockIdx.Add(1)-1)%len(pool)]
}

func (c *Client) acquire(ctx context.Context) error {
	if c.dynSem != nil {
		return c.dynSem.acquire(ctx)
	}
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() {
	if c.dynSem != nil {
		c.dynSem.release()
		return
	}
	<-c.sem
}

// pickResolver chooses the resolver index for an attempt. prevIdx is the
// resolver used by the previous attempt (-1 for the initial send).
func (c *Client) pickResolver(attempt, prevIdx int) int {
	// sticky: keep hitting the same resolver on retries (massdns --sticky).
	if c.sticky && attempt > 0 && prevIdx >= 0 {
		return prevIdx
	}
	// predictable: sequential assignment across the pool (massdns --predictable).
	if c.predictable {
		return int(c.predSeq.Add(1)-1) % len(c.resolvers)
	}
	// health scoring de-weights failing resolvers via power-of-two-choices.
	if c.health != nil {
		return c.health.pick()
	}
	// default: rotate per attempt so retries hit a different server.
	// math/rand/v2 top-level funcs are safe for concurrent use and use a
	// per-P source, so there is no shared-lock contention here.
	return (rand.IntN(len(c.resolvers)) + attempt) % len(c.resolvers)
}

// queryBufPool recycles the small byte buffers used to encode outgoing queries
// so the hot send path does not allocate per query/retransmit.
var queryBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 256); return &b }}

// chooseTarget selects the resolver for an attempt. Per-name (extended-input)
// resolvers are tried first, in order, before falling back to the global pool.
// A returned resolverIdx of -1 means a per-name resolver (not health-tracked).
func (c *Client) chooseTarget(attempt, prevIdx int, extra []*net.UDPAddr) (int, *net.UDPAddr) {
	if attempt < len(extra) {
		return -1, extra[attempt]
	}
	idx := c.pickResolver(attempt, prevIdx)
	return idx, c.resolverAddrs[idx]
}

// register allocates a transaction id and inserts the in-flight query into the
// socket table. It returns the registered query, or nil if the id space is
// saturated (in which case the name is failed).
func (c *Client) register(s *socket, name, fqdn string, attempt, resolverIdx int, addr *net.UDPAddr, extra []*net.UDPAddr) *query {
	s.mu.Lock()
	txid, ok := c.allocTxID(s)
	if !ok {
		s.mu.Unlock()
		c.fail(name, errors.New("transaction id space exhausted"))
		return nil
	}
	now := time.Now()
	q := &query{
		name:        name,
		fqdn:        fqdn,
		txid:        txid,
		resolverIdx: resolverIdx,
		addr:        addr,
		extra:       extra,
		sentAt:      now,
		deadline:    now.Add(c.opts.Timeout),
		attempts:    attempt,
		sock:        s,
	}
	s.inflight[txid] = q
	s.mu.Unlock()

	if c.hasSendHooks {
		if attempt == 0 {
			c.fireQuery(q)
		} else {
			c.fireRetry(q)
		}
	}
	return q
}

// cachedAddr resolves a resolver spec to a UDP address, caching the result so
// repeated extended-input lines don't re-parse the same string.
func (c *Client) cachedAddr(spec string) *net.UDPAddr {
	if v, ok := c.addrCache.Load(spec); ok {
		return v.(*net.UDPAddr)
	}
	addr, err := net.ResolveUDPAddr("udp", normalizeResolver(spec))
	if err != nil {
		c.addrCache.Store(spec, (*net.UDPAddr)(nil))
		return nil
	}
	c.addrCache.Store(spec, addr)
	return addr
}

// parseLine splits an input line into a name and (in extended-input mode) its
// per-name resolver addresses.
func (c *Client) parseLine(line string) (string, []*net.UDPAddr) {
	if !c.extInput {
		return strings.TrimSpace(line), nil
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	var extra []*net.UDPAddr
	for _, r := range fields[1:] {
		if a := c.cachedAddr(r); a != nil {
			extra = append(extra, a)
		}
	}
	return fields[0], extra
}

// encodeQuery writes the wire-format query for q into buf, using the hand-rolled
// fast path and falling back to miekg for names it cannot encode. Returns the
// packed bytes, or nil on a fatal encoding error.
func (c *Client) encodeQuery(buf []byte, q *query) []byte {
	packed, ok := packQuery(buf[:0], q.txid, q.name, c.opts.QueryType, c.rd, c.udpSize)
	if ok {
		return packed
	}
	msg := new(dns.Msg)
	msg.SetQuestion(q.fqdn, c.opts.QueryType)
	msg.RecursionDesired = c.rd
	msg.Id = q.txid
	if c.udpSize >= 512 {
		msg.SetEdns0(c.udpSize, false)
	}
	p, err := msg.Pack()
	if err != nil {
		return nil
	}
	return p
}

// send builds and transmits a single query, registering it in the socket
// in-flight table. attempt is the zero-based retransmission count. It is used
// for retransmissions and on the non-batched (IPv6/mixed) path.
func (c *Client) send(s *socket, name string, attempt, prevIdx int, extra []*net.UDPAddr) {
	if c.limiter != nil {
		c.limiter.take()
	}

	idx, addr := c.chooseTarget(attempt, prevIdx, extra)
	if s == nil {
		s = c.pickSocket(addr)
	}
	if s == nil {
		c.fail(name, errors.New("no socket for resolver address family"))
		return
	}
	q := c.register(s, name, dns.Fqdn(name), attempt, idx, addr, extra)
	if q == nil {
		return
	}

	bufp := queryBufPool.Get().(*[]byte)
	packed := c.encodeQuery(*bufp, q)
	if packed == nil {
		queryBufPool.Put(bufp)
		c.remove(s, q.txid)
		c.fail(name, errors.New("could not encode query"))
		return
	}
	*bufp = packed // keep any grown backing array for reuse

	var werr error
	if s.rawFD >= 0 {
		src := c.srcRand.pick()
		dport := uint16(q.addr.Port)
		if dport == 0 {
			dport = 53
		}
		werr = writeRawUDPv6(s.rawFD, src, q.addr.IP, rawSrcPort, dport, packed)
	} else {
		_, werr = s.conn.WriteToUDP(packed, q.addr)
	}
	queryBufPool.Put(bufp)
	if werr != nil {
		// transient write error: let the timeout loop retry it
		return
	}
}

// dispatchSingle sends one datagram per syscall. Used when batching is
// unavailable (IPv6/mixed resolver set).
func (c *Client) dispatchSingle(ctx context.Context, input <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case name, ok := <-input:
			if !ok {
				return
			}
			pname, extra := c.parseLine(name)
			if pname == "" {
				continue
			}
			if err := c.acquire(ctx); err != nil {
				return
			}
			c.pending.Add(1)
			c.statQueries.Add(1)
			// socket is chosen inside send() once the target resolver family is known
			c.send(nil, pname, 0, -1, extra)
		}
	}
}

// dispatchBatched coalesces outbound queries and flushes them with a single
// sendmmsg (on Linux) per socket, amortizing the per-datagram syscall cost that
// otherwise caps single-threaded send throughput. Each batch targets one socket
// (rotated per batch); individual messages may target different resolvers.
func (c *Client) dispatchBatched(ctx context.Context, input <-chan string) {
	bufs := make([][]byte, c.batchSize)
	msgs := make([]ipv4.Message, c.batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 0, 512)
		msgs[i].Buffers = [][]byte{nil}
	}

	var sockIdx uint64
	for {
		// block for the first name of a batch
		name, ok := c.nextName(ctx, input)
		if !ok {
			return
		}

		s := c.sockets[int(atomic.AddUint64(&sockIdx, 1))%len(c.sockets)]
		n := 0
		for {
			if c.limiter != nil {
				c.limiter.take()
			}
			if err := c.acquire(ctx); err != nil {
				// flush what we have before bailing out
				c.flushBatch(s, msgs[:n])
				return
			}
			c.pending.Add(1)
			c.statQueries.Add(1)

			pname, extra := c.parseLine(name)
			idx, addr := c.chooseTarget(0, -1, extra)
			q := c.register(s, pname, dns.Fqdn(pname), 0, idx, addr, extra)
			if q != nil {
				packed := c.encodeQuery(bufs[n][:0], q)
				if packed == nil {
					c.remove(s, q.txid)
					c.fail(pname, errors.New("could not encode query"))
				} else {
					bufs[n] = packed
					msgs[n].Buffers[0] = packed
					msgs[n].Addr = q.addr
					n++
				}
			}

			if n == c.batchSize {
				break
			}
			// opportunistically pull more already-queued names without blocking
			var more bool
			name, ok, more = c.tryNextName(input)
			if !ok {
				// input closed: flush and finish
				c.flushBatch(s, msgs[:n])
				return
			}
			if !more {
				break // nothing immediately available; flush the partial batch
			}
		}
		c.flushBatch(s, msgs[:n])
	}
}

// flushBatch transmits a prepared batch. It uses sendmmsg only when batching is
// active and the batch is large enough to be worth the header-array setup;
// otherwise it sends each datagram with a plain sendto. Unsent messages
// (partial write / error) stay in the in-flight table and are recovered by the
// timeout loop.
func (c *Client) flushBatch(s *socket, msgs []ipv4.Message) {
	if len(msgs) == 0 {
		return
	}
	if !c.batchActive.Load() || len(msgs) < minBatchToMMSG {
		for i := range msgs {
			if addr, ok := msgs[i].Addr.(*net.UDPAddr); ok {
				_, _ = s.conn.WriteToUDP(msgs[i].Buffers[0], addr)
			}
		}
		return
	}
	for off := 0; off < len(msgs); {
		n, err := s.pc.WriteBatch(msgs[off:], 0)
		if err != nil || n <= 0 {
			return
		}
		off += n
	}
}

// nextName blocks for the next non-empty name, returning ok=false when the
// input is closed or the context is cancelled.
func (c *Client) nextName(ctx context.Context, input <-chan string) (string, bool) {
	for {
		select {
		case <-ctx.Done():
			return "", false
		case name, ok := <-input:
			if !ok {
				return "", false
			}
			if name = strings.TrimSpace(name); name != "" {
				return name, true
			}
		}
	}
}

// tryNextName does a non-blocking read of the next name. more=false means no
// name is immediately available (the caller should flush its partial batch);
// ok=false means the input channel is closed.
func (c *Client) tryNextName(input <-chan string) (name string, ok, more bool) {
	for {
		select {
		case n, chOpen := <-input:
			if !chOpen {
				return "", false, false
			}
			if n = strings.TrimSpace(n); n != "" {
				return n, true, true
			}
			// skip empty, keep trying without blocking
		default:
			return "", true, false
		}
	}
}

// packQuery encodes a minimal DNS query (single question) into buf, returning
// the filled slice and true. rd sets the recursion-desired flag; when udpSize
// >= 512 an EDNS0 OPT record advertising that payload size is appended. It
// returns false for names it cannot encode (empty/oversized labels), so the
// caller can fall back to the general encoder.
func packQuery(buf []byte, id uint16, name string, qtype uint16, rd bool, udpSize uint16) ([]byte, bool) {
	var flagHi byte
	if rd {
		flagHi = 0x01 // recursion desired
	}
	var arcount byte
	if udpSize >= 512 {
		arcount = 0x01 // one additional record (OPT)
	}
	buf = append(buf,
		byte(id>>8), byte(id),
		flagHi, 0x00, // flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, arcount, // ARCOUNT
	)

	name = strings.TrimSuffix(name, ".")
	start := 0
	for i := 0; i <= len(name); i++ {
		if i < len(name) && name[i] != '.' {
			continue
		}
		l := i - start
		if l == 0 || l > 63 {
			// empty label (leading/double dot) or oversized label
			return buf, false
		}
		buf = append(buf, byte(l))
		buf = append(buf, name[start:i]...)
		start = i + 1
	}
	buf = append(buf, 0x00) // root label terminator

	buf = append(buf, byte(qtype>>8), byte(qtype), 0x00, 0x01) // qtype, qclass IN

	if udpSize >= 512 {
		// EDNS0 OPT pseudo-record: root name, type OPT(41), class=UDP payload
		// size, extended-rcode/flags/version=0, rdlen=0.
		buf = append(buf,
			0x00,       // root name
			0x00, 0x29, // type OPT (41)
			byte(udpSize>>8), byte(udpSize), // requestor UDP payload size
			0x00, 0x00, 0x00, 0x00, // ext-rcode, version, flags
			0x00, 0x00, // rdlen = 0
		)
	}

	if len(buf) > 512 {
		return buf, false
	}
	return buf, true
}

// allocTxID finds a free transaction id in the socket table. Caller holds s.mu.
func (c *Client) allocTxID(s *socket) (uint16, bool) {
	for i := 0; i < maxTxIDAttempts; i++ {
		id := uint16(rand.Uint32())
		if _, exists := s.inflight[id]; !exists {
			return id, true
		}
	}
	return 0, false
}

func (c *Client) remove(s *socket, txid uint16) *query {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.inflight[txid]
	if !ok {
		return nil
	}
	delete(s.inflight, txid)
	return q
}

// fail abandons a name after exhausting retries (or a fatal send error).
func (c *Client) fail(name string, err error) {
	if c.opts.OnError != nil {
		c.opts.OnError(name, err)
	}
	c.release()
	c.pending.Done()
}

// deliver emits a final result for a name.
func (c *Client) deliver(res Result) {
	c.statAnswered.Add(1)
	if c.opts.OnResult != nil {
		c.opts.OnResult(res)
	}
	c.release()
	c.pending.Done()
}

// readLoop drains responses from a single socket. When batching is unavailable
// it always reads one datagram per syscall; when capable it reads a batch
// (recvmmsg on Linux) while batching is active and falls back to single reads
// otherwise, so the read strategy tracks the adaptive controller live.
func (c *Client) readLoop(ctx context.Context, s *socket) {
	single := make([]byte, 4096)

	var msgs []ipv4.Message
	if c.batchCapable {
		msgs = make([]ipv4.Message, c.batchSize)
		for i := range msgs {
			msgs[i].Buffers = [][]byte{make([]byte, 4096)}
		}
	}

	for {
		if c.batchCapable && c.batchActive.Load() {
			n, err := s.pc.ReadBatch(msgs, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			for i := 0; i < n; i++ {
				m := &msgs[i]
				if m.N == 0 {
					continue
				}
				src, _ := m.Addr.(*net.UDPAddr)
				c.handlePacket(s, m.Buffers[0][:m.N], src)
			}
			continue
		}

		// single-datagram read (portable path / batching disengaged / raw IPv6)
		if s.rawFD >= 0 {
			payload, addr, err := readRawUDPv6(s.rawFD, single)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			c.handlePacket(s, payload, addr)
			continue
		}
		n, addr, err := s.conn.ReadFromUDP(single)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		c.handlePacket(s, single[:n], addr)
	}
}

// sameUDPAddr reports whether two UDP addresses share IP and port.
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

// handlePacket parses a single response datagram and dispatches it. src is the
// datagram's source address, used for anti-spoofing verification.
func (c *Client) handlePacket(s *socket, packet []byte, src *net.UDPAddr) {
	resp := new(dns.Msg)
	if err := resp.Unpack(packet); err != nil {
		return
	}
	if len(resp.Question) == 0 {
		return
	}
	q := c.matchAndRemove(s, resp, src)
	if q == nil {
		return
	}
	// sample round-trip time for the controller, only when something consumes
	// it (adaptive batch/concurrency or progress reporting).
	if c.sampleRTT {
		c.lastRTTNanos.Store(int64(time.Since(q.sentAt)))
	}

	if c.hooks.OnResponse != nil {
		c.hooks.OnResponse(c.queryInfo(q), resp)
	}

	from := ""
	if src != nil {
		from = src.String()
	}
	c.handleResponse(q, resp, from)
}

// matchAndRemove correlates a response to an in-flight query and removes it.
// When source-IP verification is enabled, a reply whose source does not match
// the resolver the query was sent to is ignored and the query is left in-flight
// (so a genuine reply, or a retransmission, can still resolve it).
func (c *Client) matchAndRemove(s *socket, resp *dns.Msg, src *net.UDPAddr) *query {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.inflight[resp.Id]
	if !ok {
		return nil
	}
	// validate the question name to guard against id collisions
	if !strings.EqualFold(resp.Question[0].Name, q.fqdn) {
		return nil
	}
	// anti-spoofing: the reply must come from the resolver we queried.
	if c.verify && !sameUDPAddr(src, q.addr) {
		return nil
	}
	delete(s.inflight, resp.Id)
	return q
}

func (c *Client) shouldRetry(rcode int) bool {
	if rcode >= 0 && rcode < len(c.retryRcode) {
		return c.retryRcode[rcode]
	}
	return false
}

func (c *Client) recordHealth(idx int, ok bool) {
	if c.health == nil {
		return
	}
	transitioned, healthy := c.health.record(idx, ok)
	if transitioned && c.hooks.OnResolverState != nil && idx >= 0 && idx < len(c.resolvers) {
		c.hooks.OnResolverState(c.resolvers[idx], healthy)
	}
}

// handleResponse decides whether a response is final, must be retried, or needs
// a TCP follow-up (truncation).
func (c *Client) handleResponse(q *query, resp *dns.Msg, from string) {
	// truncated UDP answer: the resolver answered but the payload didn't fit,
	// so fetch the full record set over TCP (off the reader goroutine).
	if resp.Truncated && c.tcp {
		c.recordHealth(q.resolverIdx, true)
		if c.hooks.OnTruncated != nil {
			c.hooks.OnTruncated(c.queryInfo(q))
		}
		go c.tcpFollowup(q, from)
		return
	}

	if c.shouldRetry(resp.Rcode) && q.attempts+1 < c.opts.MaxRetries {
		c.recordHealth(q.resolverIdx, false)
		c.retry(q)
		return
	}

	c.recordHealth(q.resolverIdx, true)
	c.finalize(q, c.buildResult(q, resp, from), from)
}

// finalize delivers a result, optionally cross-checking positive answers on a
// second resolver first (off the reader goroutine).
func (c *Client) finalize(q *query, res Result, from string) {
	if c.opts.CrossCheck && res.Rcode == dns.RcodeSuccess && (len(res.A) > 0 || len(res.AAAA) > 0) {
		go c.crossVerify(q, res)
		return
	}
	c.deliver(res)
}

func (c *Client) buildResult(q *query, resp *dns.Msg, from string) Result {
	res := Result{
		Name:      q.name,
		Type:      c.opts.QueryType,
		Rcode:     resp.Rcode,
		Resolver:  from,
		Msg:       resp,
		Timestamp: time.Now(),
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			res.A = append(res.A, v.A.String())
		case *dns.AAAA:
			res.AAAA = append(res.AAAA, v.AAAA.String())
		case *dns.CNAME:
			res.CNAME = append(res.CNAME, strings.TrimSuffix(v.Target, "."))
		case *dns.NS:
			res.NS = append(res.NS, strings.TrimSuffix(v.Ns, "."))
		case *dns.PTR:
			res.PTR = append(res.PTR, strings.TrimSuffix(v.Ptr, "."))
		case *dns.MX:
			res.MX = append(res.MX, strings.TrimSuffix(v.Mx, "."))
		case *dns.TXT:
			res.TXT = append(res.TXT, v.Txt...)
		case *dns.SOA:
			res.SOA = append(res.SOA, strings.TrimSuffix(v.Ns, "."))
		}
	}
	return res
}

// tcpFollowup re-issues q over TCP to retrieve a full (untruncated) answer.
func (c *Client) tcpFollowup(q *query, from string) {
	client := &dns.Client{Net: "tcp", Timeout: c.opts.Timeout}
	m := new(dns.Msg)
	m.SetQuestion(q.fqdn, c.opts.QueryType)
	m.RecursionDesired = c.rd
	m.Id = q.txid

	resp, _, err := client.Exchange(m, q.addr.String())
	if err != nil || resp == nil {
		// TCP failed: fall back to a normal UDP retry, or give up.
		if q.attempts+1 < c.opts.MaxRetries {
			c.recordHealth(q.resolverIdx, false)
			c.retry(q)
			return
		}
		c.fail(q.name, fmt.Errorf("tcp fallback failed: %w", err))
		return
	}
	c.finalize(q, c.buildResult(q, resp, from), from)
}

// crossVerify re-resolves a positive answer on a different resolver and only
// delivers it if the two agree on the address set, providing basic protection
// against DNS poisoning/spam from a single bad resolver.
func (c *Client) crossVerify(q *query, res Result) {
	idx := c.otherResolver(q.resolverIdx)
	client := &dns.Client{Timeout: c.opts.Timeout}
	m := new(dns.Msg)
	m.SetQuestion(q.fqdn, c.opts.QueryType)
	m.RecursionDesired = c.rd
	if c.udpSize >= 512 {
		m.SetEdns0(c.udpSize, false)
	}

	resp, _, err := client.Exchange(m, c.resolverAddrs[idx].String())
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		// can't confirm: drop conservatively
		if c.hooks.OnCrossCheckFailed != nil {
			c.hooks.OnCrossCheckFailed(q.name, res.A, nil)
		}
		c.fail(q.name, errPoisonSuspected)
		return
	}
	confirm := c.buildResult(q, resp, c.resolverAddrs[idx].String())
	if sameStringSet(res.A, confirm.A) && sameStringSet(res.AAAA, confirm.AAAA) {
		c.deliver(res)
		return
	}
	if c.hooks.OnCrossCheckFailed != nil {
		c.hooks.OnCrossCheckFailed(q.name, res.A, confirm.A)
	}
	c.fail(q.name, errPoisonSuspected)
}

// otherResolver returns a resolver index different from idx (best effort).
func (c *Client) otherResolver(idx int) int {
	if len(c.resolvers) == 1 {
		return idx
	}
	for {
		if j := rand.IntN(len(c.resolvers)); j != idx {
			return j
		}
	}
}

// retry retransmits a query. Every retransmit (timeout or bad-rcode) is counted
// as a loss signal for the adaptive controller. The resolver is rotated unless
// sticky mode is set.
func (c *Client) retry(q *query) {
	c.statRetransmit.Add(1)
	attempt := q.attempts + 1
	c.send(q.sock, q.name, attempt, q.resolverIdx, q.extra)
}

// timeoutLoop scans in-flight tables and retransmits or abandons expired queries.
func (c *Client) timeoutLoop(ctx context.Context) {
	// scan at a fraction of the per-attempt timeout so a lost packet is
	// retransmitted close to its deadline instead of up to a full extra tick
	// late. Bounded below to avoid burning CPU on tiny timeouts. An explicit
	// Interval overrides the derived value (massdns -i/--interval).
	interval := c.opts.Interval
	if interval <= 0 {
		interval = c.opts.Timeout / 8
	}
	if interval < 25*time.Millisecond {
		interval = 25 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.scanExpired()
		}
	}
}

func (c *Client) scanExpired() {
	now := time.Now()
	for _, s := range c.sockets {
		var expired []*query
		s.mu.Lock()
		for id, q := range s.inflight {
			if now.After(q.deadline) {
				delete(s.inflight, id)
				expired = append(expired, q)
			}
		}
		s.mu.Unlock()

		for _, q := range expired {
			c.recordHealth(q.resolverIdx, false) // timeout = resolver miss
			if c.hooks.OnTimeout != nil {
				c.hooks.OnTimeout(c.queryInfo(q))
			}
			if q.attempts+1 < c.opts.MaxRetries {
				c.retry(q)
			} else {
				c.fail(q.name, errExhausted)
			}
		}
	}
}

// inflightDepth reports the number of currently outstanding queries, reading
// whichever semaphore implementation is in use.
func (c *Client) inflightDepth() int {
	if c.dynSem != nil {
		return c.dynSem.inflight()
	}
	return len(c.sem)
}

// controllerLoop is the runtime governor. Every adaptTick it samples smoothed
// RTT, in-flight depth and interval packet loss, then drives three independent
// (all optional) feedback mechanisms:
//
//   - adaptive batching: engage sendmmsg/recvmmsg only when RTT is high enough
//     for packets to cluster AND the pipeline is deep enough to fill batches AND
//     loss is low; back off on low-RTT links, a shallow pipeline, or rising loss
//     (bursty sendmmsg can worsen drops at a saturated buffer);
//   - adaptive concurrency (AIMD): multiplicatively shrink the in-flight cap on
//     high loss and additively grow it back as loss subsides, so we stop
//     flooding resolvers that are dropping/refusing;
//   - progress reporting: emit a Stats snapshot via OnProgress.
func (c *Client) controllerLoop(ctx context.Context) {
	ticker := time.NewTicker(adaptTick)
	defer ticker.Stop()

	const alpha = 0.3 // RTT EWMA smoothing factor
	var rttEWMA time.Duration
	lastQ, lastR := c.statQueries.Load(), c.statRetransmit.Load()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			qNow, rNow := c.statQueries.Load(), c.statRetransmit.Load()
			dq, dr := qNow-lastQ, rNow-lastR
			lastQ, lastR = qNow, rNow

			var loss float64
			if total := dq + dr; total > 0 {
				loss = float64(dr) / float64(total)
			}
			c.lastLossBits.Store(math.Float64bits(loss))

			if sample := time.Duration(c.lastRTTNanos.Load()); sample > 0 {
				if rttEWMA == 0 {
					rttEWMA = sample
				} else {
					rttEWMA = time.Duration(alpha*float64(sample) + (1-alpha)*float64(rttEWMA))
				}
			}

			depth := c.inflightDepth()

			// --- adaptive batching ---
			if c.batchCapable && c.opts.Batch == BatchAdaptive {
				active := c.batchActive.Load()
				switch {
				case active:
					if rttEWMA < adaptRTTOff || depth < c.batchSize || loss > adaptLossOff {
						active = false
					}
				default:
					if rttEWMA >= adaptRTTOn && depth >= adaptDepthRatio*c.batchSize && loss <= adaptLossOff {
						active = true
					}
				}
				c.batchActive.Store(active)
			}

			// --- adaptive concurrency (AIMD) ---
			if c.dynSem != nil {
				cap := c.dynSem.capacity()
				minCap := int(float64(c.opts.Concurrency) * concMinRatio)
				if minCap < 1 {
					minCap = 1
				}
				switch {
				case loss > concLossHigh:
					nc := int(float64(cap) * concDecrease)
					if nc < minCap {
						nc = minCap
					}
					c.dynSem.setCap(nc)
				case loss < concLossLow:
					// additive increase, ~5% of max per tick
					step := c.opts.Concurrency / 20
					if step < 1 {
						step = 1
					}
					c.dynSem.setCap(cap + step)
				}
			}

			// --- progress reporting ---
			if c.opts.OnProgress != nil {
				capNow := c.opts.Concurrency
				if c.dynSem != nil {
					capNow = c.dynSem.capacity()
				}
				c.opts.OnProgress(Stats{
					Queries:        qNow,
					Retransmits:    rNow,
					Answered:       c.statAnswered.Load(),
					InflightDepth:  depth,
					ConcurrencyCap: capNow,
					LossRate:       loss,
					RTT:            rttEWMA,
					BatchActive:    c.batchActive.Load(),
				})
			}
		}
	}
}

// Stats returns a current snapshot of resolver activity (safe to call anytime).
func (c *Client) Stats() Stats {
	capNow := c.opts.Concurrency
	if c.dynSem != nil {
		capNow = c.dynSem.capacity()
	}
	return Stats{
		Queries:        c.statQueries.Load(),
		Retransmits:    c.statRetransmit.Load(),
		Answered:       c.statAnswered.Load(),
		InflightDepth:  c.inflightDepth(),
		ConcurrencyCap: capNow,
		LossRate:       math.Float64frombits(c.lastLossBits.Load()),
		RTT:            time.Duration(c.lastRTTNanos.Load()),
		BatchActive:    c.batchActive.Load(),
	}
}

var (
	errExhausted       = errors.New("max retries exhausted")
	errPoisonSuspected = errors.New("cross-resolver disagreement (possible poisoning)")
)

// Resolve is a one-shot convenience entry point for SDK use: it builds a client
// from opts, resolves every name in names, and returns the collected results.
// Any OnResult hook set in opts is preserved (invoked in addition to
// collection). For streaming/long-running use, construct a Client with New and
// call Run directly.
func Resolve(ctx context.Context, opts Options, names []string) ([]Result, error) {
	var mu sync.Mutex
	out := make([]Result, 0, len(names))
	userOnResult := opts.OnResult
	opts.OnResult = func(r Result) {
		mu.Lock()
		out = append(out, r)
		mu.Unlock()
		if userOnResult != nil {
			userOnResult(r)
		}
	}

	client, err := New(opts)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	input := make(chan string, 1024)
	go func() {
		defer close(input)
		for _, n := range names {
			select {
			case input <- n:
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := client.Run(ctx, input); err != nil {
		return out, err
	}
	return out, nil
}

// sameStringSet reports whether a and b contain the same elements (set
// equality, ignoring order and duplicates).
func sameStringSet(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	seen := make(map[string]struct{}, len(b))
	for _, v := range b {
		seen[v] = struct{}{}
	}
	for v := range set {
		if _, ok := seen[v]; !ok {
			return false
		}
	}
	return true
}

func normalizeResolver(r string) string {
	r = strings.TrimSpace(r)
	if _, _, err := net.SplitHostPort(r); err != nil {
		return net.JoinHostPort(r, "53")
	}
	return r
}
