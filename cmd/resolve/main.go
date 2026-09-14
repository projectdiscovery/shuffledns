// Command resolve is a native, dependency-free massdns-compatible bulk resolver.
// It accepts the massdns CLI surface (obsolete flags are ignored) and writes
// results in massdns output formats via pkg/output.
//
// Examples:
//
//	resolve -r resolvers.txt -t A -o Snl names.txt > out.txt
//	resolve -r resolvers.txt --ptr 192.0.2.0/24 -o J > ptr.ndjson
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/axfr"
	"github.com/projectdiscovery/shuffledns/pkg/checkpoint"
	"github.com/projectdiscovery/shuffledns/pkg/iterative"
	"github.com/projectdiscovery/shuffledns/pkg/output"
	"github.com/projectdiscovery/shuffledns/pkg/ptr"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
	"github.com/projectdiscovery/shuffledns/pkg/shard"
	"github.com/projectdiscovery/shuffledns/pkg/zonewalk"
)

func main() {
	cfg := parseFlags()

	errOut := io.Writer(os.Stderr)
	if cfg.errorLog != "" {
		f, err := os.OpenFile(cfg.errorLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fatal("could not open error log: %v", err)
		}
		defer func() { _ = f.Close() }()
		errOut = f
	}

	var resolvers []string
	var err error
	if cfg.resolversFile != "" {
		resolvers, err = readLines(cfg.resolversFile)
		if err != nil {
			fatal("could not read resolvers: %v", err)
		}
	}
	if !cfg.iterative && len(resolvers) == 0 {
		fatal("no resolvers provided (-r); or use --iterative to recurse from root")
	}

	qtype := dns.TypeA
	if cfg.qtype != "" {
		t, ok := dns.StringToType[strings.ToUpper(cfg.qtype)]
		if !ok {
			fatal("unknown record type %q", cfg.qtype)
		}
		qtype = t
	}
	if len(cfg.ptrTargets) > 0 {
		qtype = dns.TypePTR
	}

	out := os.Stdout
	if cfg.outFile != "" {
		out, err = os.Create(cfg.outFile)
		if err != nil {
			fatal("could not create output file: %v", err)
		}
		defer func() { _ = out.Close() }()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.validate {
		runValidate(ctx, cfg, resolvers, out)
		return
	}
	if cfg.axfr != "" {
		runAXFR(ctx, cfg, resolvers, out, errOut)
		return
	}
	if cfg.zone != "" {
		runZonewalk(ctx, cfg, resolvers, out, errOut)
		return
	}

	writer, err := output.NewWriterWithConfig(out, output.Config{
		Format:        cfg.format,
		FilterRcodes:  splitCSV(cfg.filter),
		IgnoreRcodes:  splitCSV(cfg.ignore),
		OnlyQueryType: cfg.onlyType,
		FlushEach:     cfg.flush,
	})
	if err != nil {
		fatal("invalid output format: %v", err)
	}
	defer func() { _ = writer.Flush() }()

	shardCfg, err := shard.Parse(cfg.shard)
	if err != nil {
		fatal("%v", err)
	}
	var ckpt *checkpoint.Checkpoint
	if cfg.resume != "" {
		ckpt, err = checkpoint.Open(cfg.resume)
		if err != nil {
			fatal("could not open resume checkpoint: %v", err)
		}
		defer func() { _ = ckpt.Close() }()
		if n := ckpt.Resumed(); n > 0 && !cfg.quiet {
			_, _ = fmt.Fprintf(errOut, "resuming: skipping %d already-completed names\n", n)
		}
	}
	markDone := func(name string) {
		if ckpt != nil {
			_ = ckpt.Done(name)
		}
	}

	onResult := func(r resolve.Result) {
		markDone(r.Name)
		if err := writer.Write(r); err != nil {
			_, _ = fmt.Fprintf(errOut, "write error: %v\n", err)
		}
	}
	onError := func(name string, err error) {
		markDone(name)
		_ = writer.WriteFailure(name, qtype, "resolution failed")
		if err != nil && !cfg.quiet {
			_, _ = fmt.Fprintf(errOut, "%s: %v\n", name, err)
		}
	}

	input := make(chan string, 8192)
	go func() {
		defer close(input)
		raw := make(chan string, 8192)
		go func() {
			defer close(raw)
			if len(cfg.ptrTargets) > 0 {
				if err := ptr.Stream(ctx, cfg.ptrTargets, raw); err != nil {
					_, _ = fmt.Fprintf(errOut, "ptr generation error: %v\n", err)
				}
				return
			}
			produceNames(ctx, cfg.args, raw, errOut)
		}()
		for name := range raw {
			if !shardCfg.Owns(name) {
				continue
			}
			if ckpt != nil && ckpt.Has(name) {
				continue
			}
			// Stop feeding once the consumer is gone (interrupt), otherwise this
			// send blocks forever on a full buffer and leaks the producer.
			select {
			case input <- name:
			case <-ctx.Done():
				return
			}
		}
	}()

	if cfg.iterative {
		ir, err := iterative.New(iterative.Options{
			QueryType:   qtype,
			Concurrency: iterativeWorkers(cfg.concurrency),
			Timeout:     cfg.timeout,
			IPv6:        qtype == dns.TypeAAAA,
		})
		if err != nil {
			fatal("could not create iterative resolver: %v", err)
		}
		err = ir.ResolveStream(ctx, input, iterative.StreamConfig{
			QueryType: qtype,
			OnResult:  func(r *resolve.Result) { onResult(*r) },
			OnError:   onError,
		})
		// A cancelled context is a user interrupt (Ctrl-C / SIGTERM), not a
		// failure: fall through so buffered output and the checkpoint are flushed
		// by the deferred cleanups instead of being lost to os.Exit.
		if err != nil && !errors.Is(err, context.Canceled) {
			fatal("resolution failed: %v", err)
		}
	} else {
		client, err := resolve.New(resolve.Options{
			Resolvers:             resolvers,
			QueryType:             qtype,
			Concurrency:           cfg.concurrency,
			QPS:                   cfg.qps,
			MaxRetries:            cfg.retries,
			Timeout:               cfg.timeout,
			Interval:              cfg.interval,
			NoRecurse:             cfg.norecurse,
			Sticky:                cfg.sticky,
			Predictable:           cfg.predictable,
			ExtendedInput:         cfg.extendedInput,
			DisableIPVerification: cfg.disableVerifyIP,
			DisableTCPFallback:    cfg.noTCPFallback,
			Batch:                 parseBatchMode(cfg.batchMode),
			SocketCount:           cfg.socketCount,
			BindAddr:              cfg.bindAddr,
			ReadBuffer:            cfg.rcvbuf,
			WriteBuffer:           cfg.sndbuf,
			RandSrcIPv6:           cfg.randSrcIPv6,
			RandSrcIPv6File:       cfg.randSrcIPv6File,
			RetryRcodes:           cfg.retryRcodes,
			ResolverHealth:        cfg.resolverHealth,
			AdaptiveConcurrency:   cfg.adaptiveConc,
			CrossCheck:            cfg.crossCheck,
			OnResult:              onResult,
			OnError:               onError,
			OnProgress:            statusReporter(cfg, errOut),
		})
		if err != nil {
			fatal("could not create resolver: %v", err)
		}
		defer client.Close()
		// Drop root after sockets are open (massdns --drop-user/--drop-group/--root).
		if err := resolve.DropPrivileges(cfg.dropUser, cfg.dropGroup, cfg.keepRoot); err != nil {
			fatal("privilege drop: %v", err)
		}
		if err := client.Run(ctx, input); err != nil && !errors.Is(err, context.Canceled) {
			fatal("resolution failed: %v", err)
		}
	}

	if err := writer.Flush(); err != nil {
		fatal("flush failed: %v", err)
	}
}

func statusReporter(cfg config, errOut io.Writer) func(resolve.Stats) {
	if cfg.quiet || strings.EqualFold(cfg.statusFormat, "none") {
		return nil
	}
	jsonMode := strings.EqualFold(cfg.statusFormat, "json")
	return func(s resolve.Stats) {
		if jsonMode {
			_, _ = fmt.Fprintf(errOut, `{"queries":%d,"retransmits":%d,"answered":%d,"inflight":%d,"concurrency":%d,"loss":%.4f,"rtt_ms":%.2f}`+"\n",
				s.Queries, s.Retransmits, s.Answered, s.InflightDepth, s.ConcurrencyCap, s.LossRate, float64(s.RTT.Microseconds())/1000)
			return
		}
		_, _ = fmt.Fprintf(errOut, "\rprocessed: %d | answered: %d | inflight: %d | conc: %d | loss: %.1f%% | rtt: %s",
			s.Queries, s.Answered, s.InflightDepth, s.ConcurrencyCap, s.LossRate*100, s.RTT.Round(time.Microsecond))
	}
}

func iterativeWorkers(concurrency int) int {
	const max = 1024
	if concurrency <= 0 {
		return 200
	}
	if concurrency > max {
		return max
	}
	return concurrency
}

type config struct {
	resolversFile   string
	qtype           string
	format          string
	outFile         string
	concurrency     int
	qps             int
	retries         int
	timeout         time.Duration
	interval        time.Duration
	norecurse       bool
	sticky          bool
	predictable     bool
	verifyIP        bool
	disableVerifyIP bool
	extendedInput   bool
	flush           bool
	quiet           bool
	errorLog        string
	statusFormat    string
	bindAddr        string
	rcvbuf          int
	sndbuf          int
	socketCount     int
	dropUser        string
	dropGroup       string
	keepRoot        bool
	randSrcIPv6     string
	randSrcIPv6File string
	retryRcodes     []int
	batchMode       string
	noTCPFallback   bool
	resolverHealth  bool
	adaptiveConc    bool
	crossCheck      bool
	iterative       bool
	ptrTargets      []string
	filter          string
	ignore          string
	onlyType        bool
	validate        bool
	validateDomain  string
	zone            string
	axfr            string
	nsec3Dict       string
	shard           string
	resume          string
	args            []string
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runValidate(ctx context.Context, cfg config, resolvers []string, out *os.File) {
	good, report, err := resolve.ValidateResolvers(ctx, resolve.ValidateConfig{
		Resolvers:   resolvers,
		GoodDomains: splitCSV(cfg.validateDomain),
		Timeout:     cfg.timeout,
	})
	if err != nil {
		fatal("validation failed: %v", err)
	}
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	for _, r := range good {
		_, _ = fmt.Fprintln(w, r)
	}
	_, _ = fmt.Fprintf(os.Stderr, "validated %d resolvers: %d good, %d rejected\n",
		len(report), len(good), len(report)-len(good))
}

func runAXFR(ctx context.Context, cfg config, resolvers []string, out *os.File, errOut io.Writer) {
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	res, err := axfr.Attempt(ctx, axfr.Config{
		Zone:      cfg.axfr,
		Resolvers: resolvers,
		Timeout:   cfg.timeout,
		OnName:    func(name string) { _, _ = fmt.Fprintln(w, name) },
		OnNameserver: func(ns string, names int, err error) {
			if err != nil {
				_, _ = fmt.Fprintf(errOut, "axfr %s: refused/failed (%v)\n", ns, err)
			} else {
				_, _ = fmt.Fprintf(errOut, "axfr %s: transferred %d names\n", ns, names)
			}
		},
	})
	if err != nil {
		fatal("zone transfer failed: %v", err)
	}
	_, _ = fmt.Fprintf(errOut, "AXFR of %s via %s transferred %d names (%d records)\n",
		cfg.axfr, res.Nameserver, len(res.Names), res.Records)
}

func runZonewalk(ctx context.Context, cfg config, resolvers []string, out *os.File, errOut io.Writer) {
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	res, err := zonewalk.Walk(ctx, zonewalk.Config{
		Zone:      cfg.zone,
		Resolvers: resolvers,
		Timeout:   cfg.timeout,
		OnName:    func(name string) { _, _ = fmt.Fprintln(w, name) },
	})
	if err != nil {
		fatal("zone walk failed: %v", err)
	}
	if res.NSEC3 {
		_, _ = fmt.Fprintf(errOut, "zone %s is NSEC3-signed (salt=%s iterations=%d)\n",
			cfg.zone, res.NSEC3Param.Salt, res.NSEC3Param.Iterations)
		if cfg.nsec3Dict == "" {
			_, _ = fmt.Fprintf(errOut, "supply --nsec3-dict <wordlist> to harvest and crack the NSEC3 ring\n")
			return
		}
		candidates, rerr := readLines(cfg.nsec3Dict)
		if rerr != nil {
			fatal("could not read nsec3 wordlist: %v", rerr)
		}
		cres, cerr := zonewalk.CrackNSEC3(ctx, zonewalk.CrackConfig{
			Zone:       cfg.zone,
			Resolvers:  resolvers,
			Timeout:    cfg.timeout,
			Candidates: candidates,
			OnName:     func(name string) { _, _ = fmt.Fprintln(w, name) },
		})
		if cerr != nil {
			fatal("nsec3 crack failed: %v", cerr)
		}
		_, _ = fmt.Fprintf(errOut, "NSEC3 crack of %s: harvested %d hashes, recovered %d/%d names (saturated=%t)\n",
			cfg.zone, cres.HarvestedHashes, len(cres.Names), len(candidates), cres.Saturated)
		return
	}
	_, _ = fmt.Fprintf(errOut, "zone walk of %s discovered %d names\n", cfg.zone, len(res.Names))
}

func produceNames(ctx context.Context, files []string, out chan<- string, errOut io.Writer) {
	emit := func(line string) bool {
		line = strings.TrimSpace(line)
		if line == "" {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case out <- line:
			return true
		}
	}

	if len(files) == 0 {
		scanLines(os.Stdin, emit)
		return
	}
	for _, fname := range files {
		f, err := os.Open(fname)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "could not open %s: %v\n", fname, err)
			continue
		}
		cont := scanLines(f, emit)
		_ = f.Close()
		if !cont {
			return
		}
	}
}

func scanLines(f *os.File, emit func(string) bool) bool {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if !emit(scanner.Text()) {
			return false
		}
	}
	return true
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if l := strings.TrimSpace(scanner.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, scanner.Err()
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

func fatal(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
