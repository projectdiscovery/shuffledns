package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// parseFlags accepts the massdns CLI surface (plus native extensions). Flags that
// only applied to the C binary's multi-process / epoll busy-poll model are
// accepted and ignored; raw IPv6 source spoofing and privilege drop are wired.
func parseFlags() config {
	var cfg config
	var ptrList string
	var intervalMs int
	var retryCSV string
	var ignoreBusyPoll bool
	var processes int

	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `resolve — native massdns-compatible bulk DNS resolver

Usage: resolve [options] [domainlist]

Massdns-compatible flags are accepted. --processes and --busy-poll are parsed
and ignored. Native extensions (iterative, ptr, validate, zonewalk, ...) are
documented below.

`)
		fs.PrintDefaults()
	}

	// Core massdns flags (short + long aliases where Go's flag package allows).
	fs.StringVar(&cfg.resolversFile, "r", "", "file with resolver IPs (massdns -r/--resolvers)")
	fs.StringVar(&cfg.resolversFile, "resolvers", "", "alias of -r")
	fs.StringVar(&cfg.qtype, "t", "A", "record type (massdns -t/--type)")
	fs.StringVar(&cfg.qtype, "type", "A", "alias of -t")
	fs.StringVar(&cfg.format, "o", "F", "output flags (massdns -o): S/F/L/J/B + modifiers")
	fs.StringVar(&cfg.format, "output", "F", "alias of -o")
	fs.StringVar(&cfg.outFile, "w", "", "write output to file (massdns -w/--outfile)")
	fs.StringVar(&cfg.outFile, "outfile", "", "alias of -w")
	fs.IntVar(&cfg.concurrency, "s", 10000, "concurrent lookups (massdns -s/--hashmap-size)")
	fs.IntVar(&cfg.concurrency, "hashmap-size", 10000, "alias of -s")
	fs.IntVar(&cfg.retries, "c", 50, "resolve attempts before giving up (massdns -c/--resolve-count)")
	fs.IntVar(&cfg.retries, "resolve-count", 50, "alias of -c")
	fs.IntVar(&intervalMs, "i", 500, "retransmit interval in ms (massdns -i/--interval)")
	fs.IntVar(&intervalMs, "interval", 500, "alias of -i")
	fs.DurationVar(&cfg.timeout, "timeout", 0, "per-attempt timeout (0 = 2×interval)")
	fs.BoolVar(&cfg.norecurse, "norecurse", false, "send non-recursive queries (RD=0)")
	fs.BoolVar(&cfg.sticky, "sticky", false, "do not rotate resolver on retry")
	fs.BoolVar(&cfg.predictable, "predictable", false, "use resolvers incrementally")
	fs.BoolVar(&cfg.verifyIP, "verify-ip", false, "verify reply source IP (massdns --verify-ip)")
	fs.BoolVar(&cfg.extendedInput, "extended-input", false, "input lines: name [resolver ...]")
	fs.BoolVar(&cfg.flush, "flush", false, "flush output after every reply")
	fs.BoolVar(&cfg.quiet, "q", false, "quiet mode (suppress status)")
	fs.BoolVar(&cfg.quiet, "quiet", false, "alias of -q")
	fs.StringVar(&cfg.errorLog, "l", "", "error log file path (default stderr)")
	fs.StringVar(&cfg.errorLog, "error-log", "", "alias of -l")
	fs.StringVar(&cfg.statusFormat, "status-format", "ansi", "status updates: ansi|json|none")
	fs.StringVar(&cfg.bindAddr, "b", "", "local bind address (massdns -b/--bindto)")
	fs.StringVar(&cfg.bindAddr, "bindto", "", "alias of -b")
	fs.IntVar(&cfg.rcvbuf, "rcvbuf", 0, "SO_RCVBUF bytes (0 = default large buffer)")
	fs.IntVar(&cfg.sndbuf, "sndbuf", 0, "SO_SNDBUF bytes (0 = OS default)")
	fs.IntVar(&cfg.socketCount, "socket-count", 0, "UDP sockets (0 = scale to cores)")
	fs.StringVar(&cfg.filter, "filter", "", "only output these response codes")
	fs.StringVar(&cfg.ignore, "ignore", "", "drop these response codes")
	fs.StringVar(&retryCSV, "retry", "", "response codes that trigger retry (default: all but NOERROR,NXDOMAIN)")

	// Rate / native engine controls.
	fs.IntVar(&cfg.qps, "qps", 0, "max outbound queries per second (0 = unlimited)")
	fs.StringVar(&cfg.batchMode, "batch-mode", "off", "datagram batching: off|on|adaptive (Linux)")
	fs.BoolVar(&cfg.noTCPFallback, "no-tcp-fallback", false, "disable TCP fallback on truncated answers")
	fs.BoolVar(&cfg.resolverHealth, "resolver-health", false, "de-weight failing resolvers")
	fs.BoolVar(&cfg.adaptiveConc, "adaptive-concurrency", false, "adapt in-flight concurrency to loss")
	fs.BoolVar(&cfg.crossCheck, "cross-check", false, "re-verify positives on a second resolver")

	// Native extensions (not in massdns).
	fs.BoolVar(&cfg.iterative, "iterative", false, "recurse from root servers (no -r needed)")
	fs.StringVar(&ptrList, "ptr", "", "reverse-PTR sweep targets: IPs/CIDRs/ranges")
	fs.BoolVar(&cfg.onlyType, "only-type", false, "output only answer records matching the queried type")
	fs.BoolVar(&cfg.validate, "validate", false, "validate the -r resolver list and print the good ones")
	fs.StringVar(&cfg.validateDomain, "validate-domain", "", "known-good domains for --validate")
	fs.StringVar(&cfg.zone, "zonewalk", "", "NSEC zone-walk the given zone")
	fs.StringVar(&cfg.axfr, "axfr", "", "AXFR/IXFR the given zone")
	fs.StringVar(&cfg.nsec3Dict, "nsec3-dict", "", "wordlist to crack NSEC3 from --zonewalk")
	fs.StringVar(&cfg.shard, "shard", "", "process shard m/n (e.g. 2/8)")
	fs.StringVar(&cfg.resume, "resume", "", "checkpoint file for crash-safe resume")

	// Privilege drop (after sockets open) and Linux raw IPv6 source spoofing.
	fs.StringVar(&cfg.dropUser, "drop-user", "", "drop privileges to user after open (default nobody when root)")
	fs.StringVar(&cfg.dropGroup, "drop-group", "", "drop privileges to group after open (default nobody when root)")
	fs.BoolVar(&cfg.keepRoot, "root", false, "do not drop privileges when running as root")
	fs.StringVar(&cfg.randSrcIPv6, "rand-src-ipv6", "", "random IPv6 source from prefix (Linux, CAP_NET_RAW; e.g. 2001:db8::/32)")
	fs.StringVar(&cfg.randSrcIPv6File, "rand-src-ipv6-file", "", "file of IPv6 source addresses (Linux, CAP_NET_RAW)")

	// Accepted and ignored (massdns multi-process / epoll busy-poll).
	fs.BoolVar(&ignoreBusyPoll, "busy-poll", false, "ignored (epoll busy-poll; not applicable)")
	fs.IntVar(&processes, "processes", 1, "ignored (use -s / sockets instead of processes)")
	_ = ignoreBusyPoll

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	cfg.args = fs.Args()
	cfg.ptrTargets = splitCSV(ptrList)
	cfg.interval = time.Duration(intervalMs) * time.Millisecond
	if cfg.timeout <= 0 {
		cfg.timeout = 2 * cfg.interval
		if cfg.timeout < time.Second {
			cfg.timeout = time.Second
		}
	}
	if retryCSV != "" {
		cfg.retryRcodes = parseRetryRcodes(retryCSV)
	}
	if processes > 1 && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "note: --processes=%d ignored; raise -s/--socket-count instead\n", processes)
	}
	if (cfg.randSrcIPv6 != "" || cfg.randSrcIPv6File != "") && cfg.bindAddr != "" {
		fmt.Fprintln(os.Stderr, "error: --bindto and --rand-src-ipv6 cannot be used together")
		os.Exit(2)
	}
	// massdns --verify-ip is opt-in; without it, skip source verification.
	cfg.disableVerifyIP = !cfg.verifyIP
	return cfg
}

func parseRetryRcodes(csv string) []int {
	var out []int
	for _, p := range splitCSV(csv) {
		if v, ok := dns.StringToRcode[strings.ToUpper(p)]; ok {
			out = append(out, v)
			continue
		}
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}
