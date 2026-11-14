package iterative

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// buildBenchHierarchy creates a wide tree: one root, one .com TLD, and `domains`
// registrable domains each served by its own authoritative server with `hosts`
// names. This models a real bruteforce workload (many names under relatively
// few registrable domains), where the delegation cache should collapse to ~1
// upstream query per name after warmup.
func buildBenchHierarchy(domains, hosts int) (*memHierarchy, []string) {
	h := newHierarchy()
	const rootIP = "127.0.0.1"
	const comIP = "127.0.1.1"

	root := h.server(rootIP).authoritative(".")
	root.delegate("com.", memNS{name: "a.gtld.net.", ip: comIP})

	com := h.server(comIP).authoritative("com.")

	var names []string
	for d := 0; d < domains; d++ {
		zone := fmt.Sprintf("d%d.com.", d)
		authIP := ip4(4096 + d) // distinct 127.0.x.y per domain
		com.delegate(zone, memNS{name: fmt.Sprintf("ns.%s", zone), ip: authIP})
		auth := h.server(authIP).authoritative(zone)
		auth.a(fmt.Sprintf("ns.%s", zone), authIP)
		for n := 0; n < hosts; n++ {
			name := fmt.Sprintf("host%d.d%d.com", n, d)
			auth.a(canonical(name), fmt.Sprintf("10.%d.%d.%d", byte(d>>8), byte(d), n%254+1))
			names = append(names, name)
		}
	}
	return h, names
}

// TestIterativeBenchmark reports throughput, TTFR, and the cache win
// (upstream queries per name). Gated behind ITER_BENCH=1 so it doesn't run in
// normal CI. No real traffic: the hierarchy is fully in-memory.
//
//	ITER_BENCH=1 go test ./pkg/iterative -run TestIterativeBenchmark -v
func TestIterativeBenchmark(t *testing.T) {
	if os.Getenv("ITER_BENCH") == "" {
		t.Skip("set ITER_BENCH=1 to run the iterative resolver benchmark")
	}
	domains, hosts, concurrency := 200, 500, 256
	h, names := buildBenchHierarchy(domains, hosts)

	r, err := New(Options{
		RootServers: []string{"127.0.0.1"},
		QueryType:   dns.TypeA,
		Concurrency: concurrency,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.newExchanger = h.factory()

	in := make(chan string, 4096)
	go func() {
		defer close(in)
		for _, n := range names {
			in <- n
		}
	}()

	var resolved, ttfrOnce atomic.Int64
	start := time.Now()
	var ttfr time.Duration
	err = r.ResolveStream(context.Background(), in, StreamConfig{
		OnResult: func(res *resolve.Result) {
			if len(res.A) > 0 {
				if ttfrOnce.CompareAndSwap(0, 1) {
					ttfr = time.Since(start)
				}
				resolved.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wall := time.Since(start)

	total := len(names)
	upstream := h.queries.Load()
	t.Logf("names=%d domains=%d hosts/domain=%d concurrency=%d", total, domains, hosts, concurrency)
	t.Logf("resolved=%d  wall=%s  qps=%.0f  ttfr=%s", resolved.Load(), wall.Round(time.Millisecond), float64(total)/wall.Seconds(), ttfr.Round(time.Microsecond))
	t.Logf("upstream queries=%d  queries/name=%.3f  (cache win: ->1.0 means root/TLD/zone walked once)", upstream, float64(upstream)/float64(total))

	if resolved.Load() != int64(total) {
		t.Fatalf("expected all %d names resolved, got %d", total, resolved.Load())
	}
}

// BenchmarkIterativeStream is a standard go benchmark of warm-cache resolution
// throughput (algorithm + cache + concurrency overhead, no network).
func BenchmarkIterativeStream(b *testing.B) {
	h, names := buildBenchHierarchy(50, 200)
	r, _ := New(Options{RootServers: []string{"127.0.0.1"}, QueryType: dns.TypeA, Concurrency: 128})
	r.newExchanger = h.factory()

	// warm the cache once
	warm := make(chan string, len(names))
	for _, n := range names {
		warm <- n
	}
	close(warm)
	_ = r.ResolveStream(context.Background(), warm, StreamConfig{OnResult: func(*resolve.Result) {}})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		in := make(chan string, len(names))
		for _, n := range names {
			in <- n
		}
		close(in)
		_ = r.ResolveStream(context.Background(), in, StreamConfig{OnResult: func(*resolve.Result) {}})
	}
}
