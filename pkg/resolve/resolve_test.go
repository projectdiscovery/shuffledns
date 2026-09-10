package resolve

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// startTestServer spins up an in-process UDP DNS server that answers A queries
// for names present in the zone map and NXDOMAIN otherwise.
func startTestServer(t *testing.T, zone map[string]string) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			if ip, ok := zone[q.Name]; ok && q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip))
				m.Answer = append(m.Answer, rr)
			} else {
				m.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()

	// give the server a moment to start
	time.Sleep(50 * time.Millisecond)

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestResolveBasic(t *testing.T) {
	zone := map[string]string{
		"a.example.com.": "1.1.1.1",
		"b.example.com.": "2.2.2.2",
		"c.example.com.": "3.3.3.3",
	}
	addr, stop := startTestServer(t, zone)
	defer stop()

	var mu sync.Mutex
	got := make(map[string][]string)
	nx := make(map[string]struct{})

	client, err := New(Options{
		Resolvers:   []string{addr},
		Concurrency: 100,
		SocketCount: 2,
		Timeout:     time.Second,
		MaxRetries:  2,
		OnResult: func(r Result) {
			mu.Lock()
			defer mu.Unlock()
			switch r.Rcode {
			case dns.RcodeSuccess:
				got[r.Name] = r.A
			case dns.RcodeNameError:
				nx[r.Name] = struct{}{}
			}
		},
	})
	require.NoError(t, err)
	defer client.Close()

	input := make(chan string)
	go func() {
		defer close(input)
		for _, n := range []string{"a.example.com", "b.example.com", "c.example.com", "missing.example.com"} {
			input <- n
		}
	}()

	require.NoError(t, client.Run(context.Background(), input))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"1.1.1.1"}, got["a.example.com"])
	require.Equal(t, []string{"2.2.2.2"}, got["b.example.com"])
	require.Equal(t, []string{"3.3.3.3"}, got["c.example.com"])
	require.Contains(t, nx, "missing.example.com")
}

// TestResolveBatchModes verifies that every batching strategy resolves the same
// set of names correctly. Batching only changes the send/recv syscall path, so
// results must be identical regardless of mode (on platforms without
// sendmmsg/recvmmsg the batch path transparently degrades to single I/O).
func TestResolveBatchModes(t *testing.T) {
	zone := make(map[string]string)
	const total = 1500
	for i := 0; i < total; i++ {
		zone[fmt.Sprintf("host%d.example.com.", i)] = fmt.Sprintf("10.1.%d.%d", i/256, i%256)
	}
	addr, stop := startTestServer(t, zone)
	defer stop()

	for _, tc := range []struct {
		name string
		mode BatchMode
	}{
		{"disabled", BatchDisabled},
		{"enabled", BatchEnabled},
		{"adaptive", BatchAdaptive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			seen := make(map[string]struct{})

			client, err := New(Options{
				Resolvers:   []string{addr},
				Concurrency: 500,
				SocketCount: 4,
				Timeout:     time.Second,
				MaxRetries:  3,
				Batch:       tc.mode,
				BatchSize:   16,
				OnResult: func(r Result) {
					if r.Rcode == dns.RcodeSuccess && len(r.A) > 0 {
						mu.Lock()
						seen[r.Name] = struct{}{}
						mu.Unlock()
					}
				},
			})
			require.NoError(t, err)
			defer client.Close()

			input := make(chan string)
			go func() {
				defer close(input)
				for i := 0; i < total; i++ {
					input <- fmt.Sprintf("host%d.example.com", i)
				}
			}()

			require.NoError(t, client.Run(context.Background(), input))

			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, total, len(seen), "all names should resolve in %s mode", tc.name)
		})
	}
}

// TestRecordTypesAndFlags spins up a server that records the recursion-desired
// bit and EDNS0 presence, answers TXT, and verifies the resolver encodes
// queries correctly (EDNS0 on by default, RD configurable) and parses TXT.
func TestRecordTypesAndFlags(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	var sawEDNS, sawRD atomic.Bool
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.IsEdns0() != nil {
			sawEDNS.Store(true)
		}
		if r.RecursionDesired {
			sawRD.Store(true)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeTXT {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN TXT \"hello-world\"", r.Question[0].Name))
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	time.Sleep(50 * time.Millisecond)
	addr := pc.LocalAddr().String()

	var mu sync.Mutex
	var txt []string
	client, err := New(Options{
		Resolvers:   []string{addr},
		QueryType:   dns.TypeTXT,
		Concurrency: 16,
		SocketCount: 1,
		Timeout:     time.Second,
		MaxRetries:  2,
		NoRecurse:   true, // RD must NOT be set
		OnResult: func(r Result) {
			mu.Lock()
			txt = append(txt, r.TXT...)
			mu.Unlock()
		},
	})
	require.NoError(t, err)
	defer client.Close()

	input := make(chan string, 1)
	input <- "example.com"
	close(input)
	require.NoError(t, client.Run(context.Background(), input))

	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, txt, "hello-world", "TXT record should be parsed")
	require.True(t, sawEDNS.Load(), "queries should advertise EDNS0 by default")
	require.False(t, sawRD.Load(), "NoRecurse should clear the RD bit")
}

// TestAllFeaturesEnabled verifies that turning on the full feature set (health
// scoring, adaptive concurrency, adaptive batching, cross-check, source
// verification, TCP fallback) still resolves every name correctly.
func TestAllFeaturesEnabled(t *testing.T) {
	zone := make(map[string]string)
	const total = 1000
	for i := 0; i < total; i++ {
		zone[fmt.Sprintf("h%d.example.com.", i)] = fmt.Sprintf("10.2.%d.%d", i/256, i%256)
	}
	addr1, stop1 := startTestServer(t, zone)
	defer stop1()
	addr2, stop2 := startTestServer(t, zone)
	defer stop2()

	var mu sync.Mutex
	seen := make(map[string]struct{})
	client, err := New(Options{
		Resolvers:           []string{addr1, addr2},
		Concurrency:         300,
		SocketCount:         4,
		Timeout:             time.Second,
		MaxRetries:          3,
		Batch:               BatchAdaptive,
		ResolverHealth:      true,
		AdaptiveConcurrency: true,
		CrossCheck:          true,
		OnResult: func(r Result) {
			if r.Rcode == dns.RcodeSuccess && len(r.A) > 0 {
				mu.Lock()
				seen[r.Name] = struct{}{}
				mu.Unlock()
			}
		},
	})
	require.NoError(t, err)
	defer client.Close()

	input := make(chan string)
	go func() {
		defer close(input)
		for i := 0; i < total; i++ {
			input <- fmt.Sprintf("h%d.example.com", i)
		}
	}()
	require.NoError(t, client.Run(context.Background(), input))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, total, len(seen), "all names should resolve with all features enabled")
}

// TestHooks verifies the lifecycle hooks fire and that the package-level
// Resolve convenience entry point collects results.
func TestHooks(t *testing.T) {
	zone := map[string]string{
		"a.example.com.": "1.1.1.1",
		"b.example.com.": "2.2.2.2",
	}
	addr, stop := startTestServer(t, zone)
	defer stop()

	var queries, responses atomic.Int64

	results, err := Resolve(context.Background(), Options{
		Resolvers:   []string{addr},
		Concurrency: 16,
		SocketCount: 1,
		Timeout:     time.Second,
		MaxRetries:  2,
		Hooks: Hooks{
			OnQuery:    func(QueryInfo) { queries.Add(1) },
			OnResponse: func(QueryInfo, *dns.Msg) { responses.Add(1) },
		},
	}, []string{"a.example.com", "b.example.com", "missing.example.com"})
	require.NoError(t, err)

	require.Len(t, results, 3, "Resolve should collect a result per name")
	require.GreaterOrEqual(t, queries.Load(), int64(3), "OnQuery should fire per name")
	require.GreaterOrEqual(t, responses.Load(), int64(3), "OnResponse should fire per answered query")
}

// TestHookTimeout verifies OnTimeout fires when a resolver never answers.
func TestHookTimeout(t *testing.T) {
	// a black-hole UDP socket that accepts but never replies
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	var timeouts atomic.Int64
	client, err := New(Options{
		Resolvers:   []string{pc.LocalAddr().String()},
		Concurrency: 4,
		SocketCount: 1,
		Timeout:     100 * time.Millisecond,
		MaxRetries:  2,
		Hooks:       Hooks{OnTimeout: func(QueryInfo) { timeouts.Add(1) }},
	})
	require.NoError(t, err)
	defer client.Close()

	input := make(chan string, 1)
	input <- "dead.example.com"
	close(input)
	require.NoError(t, client.Run(context.Background(), input))
	require.GreaterOrEqual(t, timeouts.Load(), int64(1), "OnTimeout should fire for an unanswered query")
}

func TestResolveManyNames(t *testing.T) {
	zone := make(map[string]string)
	const total = 2000
	for i := 0; i < total; i++ {
		zone[fmt.Sprintf("host%d.example.com.", i)] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	addr, stop := startTestServer(t, zone)
	defer stop()

	var count int64
	var mu sync.Mutex
	seen := make(map[string]struct{})

	client, err := New(Options{
		Resolvers:   []string{addr},
		Concurrency: 500,
		SocketCount: 4,
		Timeout:     time.Second,
		MaxRetries:  3,
		OnResult: func(r Result) {
			if r.Rcode == dns.RcodeSuccess && len(r.A) > 0 {
				mu.Lock()
				seen[r.Name] = struct{}{}
				count++
				mu.Unlock()
			}
		},
	})
	require.NoError(t, err)
	defer client.Close()

	input := make(chan string)
	go func() {
		defer close(input)
		for i := 0; i < total; i++ {
			input <- fmt.Sprintf("host%d.example.com", i)
		}
	}()

	require.NoError(t, client.Run(context.Background(), input))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, total, len(seen), "all names should resolve")
}
