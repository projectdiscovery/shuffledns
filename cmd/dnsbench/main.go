// Command dnsbench benchmarks DNS resolution engines against a battery of
// loopback resolvers that simulate remote ones (see internal/simdns). It can
// drive both the native resolver and the external massdns binary against the
// exact same simulated conditions, so the comparison is apples-to-apples.
//
// No DNS traffic leaves the host: every resolver the engines talk to is a
// 127.0.0.1:<ephemeral> UDP server started in-process. massdns is Linux-only
// (epoll), so this is intended to run inside the provided Docker image; the
// native engine runs anywhere.
//
// Example (inside the container):
//
//	dnsbench -massdns /opt/massdns/bin/massdns -names 200000 -resolvers 16 -hit 5
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/internal/simdns"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

var (
	names       = flag.Int("names", 50000, "number of names to resolve per scenario")
	resolvers   = flag.Int("resolvers", 8, "number of simulated loopback resolvers")
	hit         = flag.Int("hit", 5, "percentage of names that resolve (rest NXDOMAIN)")
	concurrency = flag.Int("concurrency", 10000, "in-flight concurrency / massdns hashmap size")
	retries     = flag.Int("retries", 5, "retry budget per name (both engines)")
	sockets     = flag.Int("sockets", 0, "native resolver udp socket count (0 = scale to cores)")
	batchMode   = flag.String("batch-mode", "off", "native batching: off | on | adaptive (sendmmsg/recvmmsg, Linux)")
	massdnsPath = flag.String("massdns", "", "path to the massdns binary (empty = skip massdns)")
	engines     = flag.String("engines", "native,massdns", "comma-separated engines to run")
	scenarios   = flag.String("scenarios", "all", "comma-separated scenario names or 'all'")
	keepFiles   = flag.Bool("keep", false, "keep generated names/resolvers files")
)

type scenario struct {
	name string
	cfg  simdns.Config
}

func parseBatchMode(s string) resolve.BatchMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "enabled", "true":
		return resolve.BatchEnabled
	case "adaptive", "auto":
		return resolve.BatchAdaptive
	default:
		return resolve.BatchDisabled
	}
}

func allScenarios(hitPct int) []scenario {
	return []scenario{
		{"lan-fast", simdns.Config{BaseLatency: 200 * time.Microsecond, Jitter: 300 * time.Microsecond, HitPercent: hitPct}},
		{"wan-typical", simdns.Config{BaseLatency: 15 * time.Millisecond, Jitter: 10 * time.Millisecond, LossRate: 0.005, HitPercent: hitPct}},
		{"wan-lossy", simdns.Config{BaseLatency: 25 * time.Millisecond, Jitter: 20 * time.Millisecond, LossRate: 0.05, ServfailRate: 0.02, HitPercent: hitPct}},
		{"rate-limited", simdns.Config{BaseLatency: 10 * time.Millisecond, Jitter: 10 * time.Millisecond, QPSPerServer: 3000, HitPercent: hitPct}},
	}
}

type result struct {
	engine   string
	ttfr     time.Duration
	wall     time.Duration
	qps      float64
	resolved int64
}

func main() {
	flag.Parse()

	selectedEngines := splitCSV(*engines)
	wantMassdns := contains(selectedEngines, "massdns")
	wantNative := contains(selectedEngines, "native")

	if wantMassdns && *massdnsPath == "" {
		// try to find it on PATH
		if p, err := exec.LookPath("massdns"); err == nil {
			*massdnsPath = p
		} else {
			fmt.Fprintln(os.Stderr, "massdns requested but -massdns not set and not found on PATH; skipping massdns")
			wantMassdns = false
		}
	}

	scns := filterScenarios(allScenarios(*hit), *scenarios)
	if len(scns) == 0 {
		fmt.Fprintln(os.Stderr, "no scenarios selected")
		os.Exit(1)
	}

	// write the shared names file once
	namesFile, err := writeNamesFile(*names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not write names file: %v\n", err)
		os.Exit(1)
	}
	if !*keepFiles {
		defer os.Remove(namesFile)
	}

	fmt.Printf("dnsbench: names=%d resolvers=%d hit=%d%% concurrency=%d retries=%d\n",
		*names, *resolvers, *hit, *concurrency, *retries)
	fmt.Printf("no traffic leaves the host; resolvers are loopback (127.0.0.1)\n\n")
	fmt.Printf("%-14s %-9s %10s %10s %12s %10s\n", "scenario", "engine", "ttfr", "wall", "qps", "resolved")
	fmt.Printf("%s\n", strings.Repeat("-", 70))

	for _, sc := range scns {
		var rows []result
		if wantNative {
			r, err := runNative(sc, namesFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "native %s failed: %v\n", sc.name, err)
			} else {
				rows = append(rows, r)
			}
		}
		if wantMassdns {
			r, err := runMassdns(sc, namesFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "massdns %s failed: %v\n", sc.name, err)
			} else {
				rows = append(rows, r)
			}
		}
		for _, r := range rows {
			fmt.Printf("%-14s %-9s %10s %10s %12.0f %10d\n",
				sc.name, r.engine,
				r.ttfr.Round(100*time.Microsecond),
				r.wall.Round(time.Millisecond),
				r.qps, r.resolved)
		}
		fmt.Printf("%s\n", strings.Repeat("-", 70))
	}
}

// perAttemptTimeout sizes a timeout/interval to a few RTTs so lossy scenarios
// complete via retransmission instead of stalling. Both engines use it.
func perAttemptTimeout(cfg simdns.Config) time.Duration {
	rtt := cfg.BaseLatency + cfg.Jitter
	t := 6 * rtt
	if t < 500*time.Millisecond {
		t = 500 * time.Millisecond
	}
	return t
}

func runNative(sc scenario, namesFile string) (result, error) {
	battery, err := simdns.Start(*resolvers, sc.cfg)
	if err != nil {
		return result{}, err
	}
	defer battery.Stop()

	timeout := perAttemptTimeout(sc.cfg)

	// pre-load names into memory (outside the timed region) so the producer is
	// never the bottleneck; we want to measure the resolver, not the scanner.
	nameList, err := loadNames(namesFile)
	if err != nil {
		return result{}, err
	}

	var resolved atomic.Int64
	var ttfrNanos atomic.Int64
	start := time.Now()

	client, err := resolve.New(resolve.Options{
		Resolvers:   battery.Addrs,
		Concurrency: *concurrency,
		SocketCount: *sockets,
		Batch:       parseBatchMode(*batchMode),
		Timeout:     timeout,
		MaxRetries:  *retries,
		OnResult: func(r resolve.Result) {
			ttfrNanos.CompareAndSwap(0, int64(time.Since(start)))
			if r.Rcode == dns.RcodeSuccess && len(r.A) > 0 {
				resolved.Add(1)
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer client.Close()

	input := make(chan string, 8192)
	go func() {
		defer close(input)
		for _, n := range nameList {
			input <- n
		}
	}()

	if err := client.Run(context.Background(), input); err != nil {
		return result{}, err
	}
	wall := time.Since(start)

	printServerStats("native", sc.name, battery.Stats)
	return result{
		engine:   "native",
		ttfr:     time.Duration(ttfrNanos.Load()),
		wall:     wall,
		qps:      float64(*names) / wall.Seconds(),
		resolved: resolved.Load(),
	}, nil
}

func runMassdns(sc scenario, namesFile string) (result, error) {
	battery, err := simdns.Start(*resolvers, sc.cfg)
	if err != nil {
		return result{}, err
	}
	defer battery.Stop()

	resolversFile, err := writeResolversFile(battery.Addrs)
	if err != nil {
		return result{}, err
	}
	if !*keepFiles {
		defer os.Remove(resolversFile)
	}

	timeout := perAttemptTimeout(sc.cfg)
	intervalMs := int(timeout / time.Millisecond)

	// -o S: simple output (answer RRs only), one line per record.
	// -s   : hashmap size / concurrent lookups.
	// -i   : retransmit interval for a name (match native per-attempt timeout).
	// -c   : resolve attempts before giving up (match native retry budget).
	args := []string{
		"-r", resolversFile,
		"-t", "A",
		"-o", "S",
		"-s", fmt.Sprintf("%d", *concurrency),
		"-i", fmt.Sprintf("%d", intervalMs),
		"-c", fmt.Sprintf("%d", *retries),
		"--flush",
		namesFile,
	}

	cmd := exec.Command(*massdnsPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return result{}, err
	}
	cmd.Stderr = nil // discard massdns progress/error log

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return result{}, err
	}

	var ttfr time.Duration
	var resolved int64
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if ttfr == 0 {
			ttfr = time.Since(start)
		}
		// simple-format A record lines look like: "name. A 10.1.2.3"
		if strings.Contains(line, " A ") {
			resolved++
		}
	}
	if err := cmd.Wait(); err != nil {
		return result{}, fmt.Errorf("massdns exited: %w", err)
	}
	wall := time.Since(start)

	printServerStats("massdns", sc.name, battery.Stats)
	return result{
		engine:   "massdns",
		ttfr:     ttfr,
		wall:     wall,
		qps:      float64(*names) / wall.Seconds(),
		resolved: resolved,
	}, nil
}

func printServerStats(engine, scenario string, s *simdns.Stats) {
	fmt.Fprintf(os.Stderr, "  [%s/%s] server-side queries=%d answered=%d dropped=%d servfail=%d ratelimited=%d\n",
		engine, scenario, s.Queries.Load(), s.Answered.Load(), s.Dropped.Load(),
		s.Servfail.Load(), s.RateLimited.Load())
}

func loadNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if n := strings.TrimSpace(scanner.Text()); n != "" {
			names = append(names, n)
		}
	}
	return names, scanner.Err()
}

func writeNamesFile(n int) (string, error) {
	f, err := os.CreateTemp("", "dnsbench-names-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for i := 0; i < n; i++ {
		if _, err := fmt.Fprintf(w, "host%d.bench.example.com\n", i); err != nil {
			return "", err
		}
	}
	return f.Name(), w.Flush()
}

func writeResolversFile(addrs []string) (string, error) {
	f, err := os.CreateTemp("", "dnsbench-resolvers-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, a := range addrs {
		if _, err := fmt.Fprintln(w, a); err != nil {
			return "", err
		}
	}
	return f.Name(), w.Flush()
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func filterScenarios(all []scenario, sel string) []scenario {
	if strings.TrimSpace(sel) == "" || strings.EqualFold(strings.TrimSpace(sel), "all") {
		return all
	}
	want := splitCSV(sel)
	var out []scenario
	for _, s := range all {
		if contains(want, s.name) {
			out = append(out, s)
		}
	}
	return out
}
