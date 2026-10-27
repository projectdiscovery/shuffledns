package resolve

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/internal/simdns"
)

// This file benchmarks the native resolver against a battery of loopback UDP
// DNS servers that simulate remote resolvers (see internal/simdns). No traffic
// leaves the host. It is gated behind RESOLVE_BENCH so `go test ./...` stays
// fast. Example:
//
//	RESOLVE_BENCH=1 go test ./pkg/resolve -run TestResolverBenchmark -v \
//	    -bench.names 200000 -bench.resolvers 16 -bench.hit 5

var (
	benchNames     = flag.Int("bench.names", 50000, "number of names to resolve per scenario")
	benchResolvers = flag.Int("bench.resolvers", 8, "number of simulated loopback resolvers")
	benchHit       = flag.Int("bench.hit", 5, "percentage of names that resolve (rest are NXDOMAIN)")
	benchConc      = flag.Int("bench.concurrency", 10000, "client in-flight concurrency")
	benchSockets   = flag.Int("bench.sockets", 8, "client udp socket count")
	benchBatch     = flag.String("bench.batch", "off", "batching mode: off | on | adaptive")
	benchHealth    = flag.Bool("bench.health", false, "enable per-resolver health scoring")
	benchAdaptConc = flag.Bool("bench.adaptconc", false, "enable adaptive concurrency")
	benchHooks     = flag.Bool("bench.hooks", false, "attach no-op lifecycle hooks (measure hook overhead)")
)

// noopHooks returns a full set of no-op lifecycle hooks for overhead testing.
func noopHooks() Hooks {
	return Hooks{
		OnQuery:            func(QueryInfo) {},
		OnRetry:            func(QueryInfo) {},
		OnResponse:         func(QueryInfo, *dns.Msg) {},
		OnTimeout:          func(QueryInfo) {},
		OnTruncated:        func(QueryInfo) {},
		OnCrossCheckFailed: func(string, []string, []string) {},
		OnResolverState:    func(string, bool) {},
	}
}

func benchBatchMode(s string) BatchMode {
	switch s {
	case "on":
		return BatchEnabled
	case "adaptive":
		return BatchAdaptive
	default:
		return BatchDisabled
	}
}

// scenario pairs a human-readable name with simulated network conditions.
type scenario struct {
	name string
	cfg  simdns.Config
}

func benchScenarios(hit int) []scenario {
	return []scenario{
		{"lan-fast", simdns.Config{BaseLatency: 200 * time.Microsecond, Jitter: 300 * time.Microsecond, HitPercent: hit}},
		{"wan-typical", simdns.Config{BaseLatency: 15 * time.Millisecond, Jitter: 10 * time.Millisecond, LossRate: 0.005, HitPercent: hit}},
		{"wan-lossy", simdns.Config{BaseLatency: 25 * time.Millisecond, Jitter: 20 * time.Millisecond, LossRate: 0.05, ServfailRate: 0.02, HitPercent: hit}},
		{"rate-limited", simdns.Config{BaseLatency: 10 * time.Millisecond, Jitter: 10 * time.Millisecond, QPSPerServer: 3000, HitPercent: hit}},
	}
}

func TestResolverBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resolver benchmark in -short mode")
	}
	if os.Getenv("RESOLVE_BENCH") == "" {
		t.Skip("set RESOLVE_BENCH=1 to run the loopback resolver benchmark")
	}

	hit := *benchHit

	t.Logf("names=%d resolvers=%d hit=%d%% concurrency=%d sockets=%d",
		*benchNames, *benchResolvers, hit, *benchConc, *benchSockets)
	t.Logf("%-14s %10s %10s %10s %10s %10s %10s",
		"scenario", "ttfr", "wall", "qps", "resolved", "nxdomain", "failed")

	for _, sc := range benchScenarios(hit) {
		runBenchmarkScenario(t, sc)
	}
}

func runBenchmarkScenario(t *testing.T, sc scenario) {
	t.Helper()

	battery, err := simdns.Start(*benchResolvers, sc.cfg)
	if err != nil {
		t.Fatalf("could not start sim resolvers: %v", err)
	}
	defer battery.Stop()

	// size the per-attempt timeout to a few RTTs so lossy scenarios still
	// complete via retransmission instead of stalling.
	rtt := sc.cfg.BaseLatency + sc.cfg.Jitter
	timeout := 6 * rtt
	if timeout < 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}

	var resolved, nxdomain, failed atomic.Int64
	var ttfrNanos atomic.Int64 // 0 until first result
	start := time.Now()

	var hooks Hooks
	if *benchHooks {
		hooks = noopHooks()
	}

	client, err := New(Options{
		Resolvers:           battery.Addrs,
		Concurrency:         *benchConc,
		SocketCount:         *benchSockets,
		Timeout:             timeout,
		MaxRetries:          5,
		Batch:               benchBatchMode(*benchBatch),
		ResolverHealth:      *benchHealth,
		AdaptiveConcurrency: *benchAdaptConc,
		Hooks:               hooks,
		OnResult: func(r Result) {
			ttfrNanos.CompareAndSwap(0, int64(time.Since(start)))
			switch {
			case r.Rcode == dns.RcodeSuccess && len(r.A) > 0:
				resolved.Add(1)
			case r.Rcode == dns.RcodeNameError:
				nxdomain.Add(1)
			default:
				failed.Add(1)
			}
		},
		OnError: func(string, error) { failed.Add(1) },
	})
	if err != nil {
		t.Fatalf("could not create client: %v", err)
	}
	defer client.Close()

	total := *benchNames
	input := make(chan string, 4096)
	go func() {
		defer close(input)
		for i := 0; i < total; i++ {
			input <- fmt.Sprintf("host%d.bench.example.com", i)
		}
	}()

	if err := client.Run(context.Background(), input); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	wall := time.Since(start)

	qps := float64(total) / wall.Seconds()
	ttfr := time.Duration(ttfrNanos.Load())

	t.Logf("%-14s %10s %10s %10.0f %10d %10d %10d",
		sc.name,
		ttfr.Round(100*time.Microsecond),
		wall.Round(time.Millisecond),
		qps,
		resolved.Load(),
		nxdomain.Load(),
		failed.Load(),
	)
	s := battery.Stats
	t.Logf("    server-side: queries=%d answered=%d dropped=%d servfail=%d ratelimited=%d",
		s.Queries.Load(), s.Answered.Load(), s.Dropped.Load(),
		s.Servfail.Load(), s.RateLimited.Load())
}
