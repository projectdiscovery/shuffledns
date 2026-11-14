// Command iterbench is a fully-local, offline benchmark that compares the
// iterative-from-root resolver against the stub resolver on the SAME workload,
// measuring both throughput and accuracy (false negatives). No packet leaves
// the host:
//
//   - the iterative engine resolves against a real-socket authoritative
//     hierarchy (internal/authsim) bound to 127.0.0.x loopback addresses;
//   - the stub engine resolves against a battery of simulated recursive
//     resolvers (internal/simdns) modelling real-world public-resolver
//     conditions (latency, loss, rate-limiting and, crucially, rate-limit /
//     hijack induced false NXDOMAIN — the massdns #117 failure mode).
//
// Both layers answer identical synthetic IPs, so any name the stub fails to
// resolve while the iterative engine succeeds is a measured false negative
// attributable to the public-resolver dependency that iterative removes.
//
// Must run on Linux (binding 127.0.0.x). The repo Dockerfile builds it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/internal/authsim"
	"github.com/projectdiscovery/shuffledns/internal/simdns"
	"github.com/projectdiscovery/shuffledns/pkg/iterative"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

func main() {
	domains := flag.Int("domains", 200, "registrable domains under .com")
	hosts := flag.Int("hosts", 250, "hostnames per domain")
	port := flag.Int("port", 5354, "shared UDP port for the authoritative hierarchy")
	iterWorkers := flag.Int("iter-workers", 256, "iterative resolver worker count")
	stubConc := flag.Int("stub-concurrency", 10000, "stub resolver in-flight concurrency")
	recursors := flag.Int("recursors", 16, "simulated recursive resolvers for the stub")
	retries := flag.Int("retries", 5, "retry budget (both engines)")
	hijack := flag.Float64("hijack", 0.15, "fraction of existing names a recursor falsely answers NXDOMAIN (massdns #117)")
	loss := flag.Float64("loss", 0.01, "recursor packet loss rate")
	servfail := flag.Float64("servfail", 0.01, "recursor SERVFAIL rate")
	flag.Parse()

	fmt.Printf("iterbench: domains=%d hosts/domain=%d names=%d\n", *domains, *hosts, *domains*(*hosts))
	fmt.Printf("no traffic leaves the host; authoritative tree on 127.0.0.x:%d, recursors on 127.0.0.1\n\n", *port)

	// ----- authoritative hierarchy (reliable, for iterative) -----
	hier, err := authsim.Build(*domains, *hosts, *port)
	if err != nil {
		fatal("could not start authoritative hierarchy: %v", err)
	}
	defer hier.Stop()
	names := hier.Names
	total := len(names)

	// ----- simulated recursive resolvers (flaky, for stub) -----
	battery, err := simdns.Start(*recursors, simdns.Config{
		BaseLatency:  1 * time.Millisecond,
		Jitter:       2 * time.Millisecond,
		LossRate:     *loss,
		ServfailRate: *servfail,
		HijackRate:   *hijack,
		HitPercent:   100, // every name exists; any miss is a false negative
	})
	if err != nil {
		fatal("could not start recursor battery: %v", err)
	}
	defer battery.Stop()

	fmt.Printf("%-12s %-10s %-10s %-12s %-10s %-12s\n", "engine", "ttfr", "wall", "qps", "resolved", "missed(FN)")
	fmt.Println("--------------------------------------------------------------------------")

	// ----- iterative engine -----
	itResolved, itTTFR, itWall := runIterative(hier, names, *iterWorkers, *retries)
	report("iterative", itTTFR, itWall, total, itResolved)
	fmt.Printf("  authoritative queries=%d  queries/name=%.3f\n", hier.Queries.Load(), float64(hier.Queries.Load())/float64(total))

	// ----- stub engine -----
	stResolved, stTTFR, stWall := runStub(battery.Addrs, names, *stubConc, *retries)
	report("stub", stTTFR, stWall, total, stResolved)
	fmt.Printf("  recursor hijacked(false NXDOMAIN)=%d servfail=%d dropped=%d ratelimited=%d\n",
		battery.Stats.Hijacked.Load(), battery.Stats.Servfail.Load(), battery.Stats.Dropped.Load(), battery.Stats.RateLimited.Load())

	fmt.Println("\nAccuracy delta (the point):")
	fmt.Printf("  iterative missed %d/%d (%.2f%%)\n", total-int(itResolved), total, 100*float64(total-int(itResolved))/float64(total))
	fmt.Printf("  stub      missed %d/%d (%.2f%%)  <- false negatives from flaky/lying recursors\n",
		total-int(stResolved), total, 100*float64(total-int(stResolved))/float64(total))
}

func runIterative(hier *authsim.Hierarchy, names []string, workers, retries int) (int64, time.Duration, time.Duration) {
	r, err := iterative.New(iterative.Options{
		RootServers: []string{hier.RootAddr},
		QueryType:   dns.TypeA,
		Concurrency: workers,
		Retries:     retries,
		Timeout:     3 * time.Second,
	})
	if err != nil {
		fatal("could not create iterative resolver: %v", err)
	}
	in := feed(names)
	var resolved, ttfrSet atomic.Int64
	var ttfr time.Duration
	start := time.Now()
	_ = r.ResolveStream(context.Background(), in, iterative.StreamConfig{
		QueryType: dns.TypeA,
		OnResult: func(res *resolve.Result) {
			if res.Rcode == dns.RcodeSuccess && len(res.A) > 0 {
				if ttfrSet.CompareAndSwap(0, 1) {
					ttfr = time.Since(start)
				}
				resolved.Add(1)
			}
		},
	})
	return resolved.Load(), ttfr, time.Since(start)
}

func runStub(resolvers, names []string, concurrency, retries int) (int64, time.Duration, time.Duration) {
	var resolved, ttfrSet atomic.Int64
	var ttfr time.Duration
	start := time.Now()
	client, err := resolve.New(resolve.Options{
		Resolvers:   resolvers,
		QueryType:   dns.TypeA,
		Concurrency: concurrency,
		MaxRetries:  retries,
		Timeout:     2 * time.Second,
		OnResult: func(r resolve.Result) {
			if r.Rcode == dns.RcodeSuccess && len(r.A) > 0 {
				if ttfrSet.CompareAndSwap(0, 1) {
					ttfr = time.Since(start)
				}
				resolved.Add(1)
			}
		},
	})
	if err != nil {
		fatal("could not create stub resolver: %v", err)
	}
	defer client.Close()
	_ = client.Run(context.Background(), feed(names))
	return resolved.Load(), ttfr, time.Since(start)
}

func feed(names []string) <-chan string {
	ch := make(chan string, 8192)
	go func() {
		defer close(ch)
		for _, n := range names {
			ch <- n
		}
	}()
	return ch
}

func report(engine string, ttfr, wall time.Duration, total int, resolved int64) {
	qps := float64(total) / wall.Seconds()
	missed := total - int(resolved)
	fmt.Printf("%-12s %-10s %-10s %-12.0f %-10d %-12d\n",
		engine, ttfr.Round(time.Microsecond), wall.Round(time.Millisecond), qps, resolved, missed)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
