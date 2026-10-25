package runner

import (
	"os"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	// DefaultBatchSize is the default number of lines per chunk for incremental processing
	DefaultBatchSize = 500000
)

// Options contains the configuration options for tuning
// the active dns resolving process.
type Options struct {
	AutoExtractRootDomains bool                // Automatically extract root domains
	Directory              string              // Directory is a directory for temporary data
	Domains                goflags.StringSlice // Domains is the list of domains to find subdomains
	SubdomainsList         string              // SubdomainsList is the file containing list of hosts to resolve
	ResolversFile          string              // ResolversFile is the file containing resolvers to use for enumeration
	TrustedResolvers       string              // TrustedResolvers is the file containing trusted resolvers
	Wordlist               string              // Wordlist is a wordlist to use for enumeration
	MassdnsPath            string              // MassdnsPath contains the path to massdns binary
	Output                 string              // Output is the file to write found subdomains to.
	Json                   bool                // Json is the format for making output as ndjson
	Silent                 bool                // Silent suppresses any extra text and only writes found host:port to screen
	Version                bool                // Version specifies if we should just show version and exit
	Retries                int                 // Retries is the number of retries for dns enumeration
	Verbose                bool                // Verbose flag indicates whether to show verbose output or not
	NoColor                bool                // No-Color disables the colored output
	Threads                int                 // Thread controls the number of parallel host to enumerate
	MassdnsRaw             string              // MassdnsRaw perform wildcards filtering from an existing massdns output file
	WildcardThreads        int                 // WildcardsThreads controls the number of parallel host to check for wildcard
	StrictWildcard         bool                // StrictWildcard flag indicates whether wildcard check has to be performed on each found subdomains
	WildcardOutputFile     string              // StrictWildcard flag indicates whether wildcard check has to be performed on each found subdomains
	MassDnsCmd             string              // Supports massdns flags(example -i)
	DisableUpdateCheck     bool                // DisableUpdateCheck disable automatic update check
	Mode                   string
	KeepStderr             bool // KeepStderr controls whether to capture and store massdns stderr output
	BatchSize              int  // BatchSize controls the number of lines per chunk for incremental processing
	FilterInternalIPs      bool // FilterInternalIPs controls whether to filter out internal/private IP addresses

	// Native resolver tuning (see pkg/resolve).
	QueryType           string // DNS record type to resolve (A, AAAA, CNAME, ...). Default A.
	BatchMode           string // sendmmsg/recvmmsg batching: off | on | adaptive
	SocketCount         int    // UDP sockets per run (0 = scale to cores)
	UDPSize             int    // EDNS0 advertised UDP payload size (0 = default 1232; <512 disables)
	QPS                 int    // outbound query rate limit (0 = unlimited)
	NoRecurse           bool   // send non-recursive queries (RD=0)
	Sticky              bool   // do not rotate resolver on retry
	ResolverHealth      bool   // per-resolver health scoring / de-weighting
	AdaptiveConcurrency bool   // shrink/grow in-flight cap based on packet loss
	CrossCheck          bool   // re-verify positive answers on a second resolver
	ExtendedInput       bool   // parse "name [resolver ...]" input lines
	NoVerifyIP          bool   // disable reply source-IP verification
	NoTCPFallback       bool   // disable TCP fallback on truncated answers
	// Iterative recurses from the root servers (no resolver list needed),
	// caching delegations; removes the public-resolver dependency.
	Iterative bool

	// Distributed resolution and resume.
	Shard      string // "m/n": process only shard m of n (distributed coordination)
	ResumeFile string // checkpoint file for crash-safe stop/resume

	OnResult func(*retryabledns.DNSData)
}

var DefaultOptions = Options{
	Threads:         10000,
	Retries:         5,
	WildcardThreads: 250,
	BatchSize:       DefaultBatchSize, // Default batch size for incremental processing
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`shuffleDNS is a high-throughput DNS bruteforcer and resolver with wildcard handling. It uses a native Go stub resolver (massdns-compatible) and optional iterative resolution from the DNS roots.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Domains, "domain", "d", nil, "Domain to find or resolve subdomains for", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.AutoExtractRootDomains, "auto-domain", "ad", false, "Automatically extract root domains"),
		flagSet.StringVarP(&options.SubdomainsList, "list", "l", "", "File containing list of subdomains to resolve"),
		flagSet.StringVarP(&options.Wordlist, "wordlist", "w", "", "File containing words to bruteforce for domain"),
		flagSet.StringVarP(&options.ResolversFile, "resolver", "r", "", "File containing list of resolvers for enumeration"),
		flagSet.StringVarP(&options.TrustedResolvers, "trusted-resolver", "tr", "", "File containing list of trusted resolvers"),
		flagSet.StringVarP(&options.MassdnsRaw, "raw-input", "ri", "", "Filter wildcards from an existing massdns-format output file"),
		flagSet.StringVar(&options.Mode, "mode", "", "Execution mode (bruteforce, resolve, filter)"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVar(&options.Threads, "t", 10000, "Max concurrent in-flight DNS queries"),
		flagSet.IntVar(&options.QPS, "qps", 0, "Max outbound DNS queries per second (0 = unlimited)"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update shuffledns to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic shuffledns update check"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to write output to (optional)"),
		flagSet.BoolVarP(&options.Json, "json", "j", false, "Make output format as ndjson"),
		flagSet.StringVarP(&options.WildcardOutputFile, "wildcard-output", "wo", "", "Dump wildcard ips to output file"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVarP(&options.MassdnsPath, "massdns", "m", "", "Deprecated: massdns is no longer used (native resolver), flag ignored"),
		flagSet.StringVarP(&options.MassDnsCmd, "massdns-cmd", "mcmd", "", "Deprecated: massdns is no longer used (native resolver), flag ignored"),
		flagSet.StringVar(&options.Directory, "directory", "", "Temporary directory for enumeration"),
	)

	flagSet.CreateGroup("optimizations", "Optimizations",
		flagSet.IntVar(&options.Retries, "retries", 5, "Number of retries for dns enumeration"),
		flagSet.BoolVarP(&options.StrictWildcard, "strict-wildcard", "sw", false, "Perform wildcard check on all found subdomains"),
		flagSet.IntVar(&options.WildcardThreads, "wt", 250, "Number of concurrent wildcard checks"),
		flagSet.BoolVar(&options.KeepStderr, "retain-stderr", false, "Deprecated: massdns is no longer used (native resolver), flag ignored"),
		flagSet.IntVar(&options.BatchSize, "batch-size", DefaultBatchSize, "Deprecated: native resolver streams without chunking, flag ignored"),
		flagSet.BoolVar(&options.FilterInternalIPs, "filter-internal-ips", false, "Filter out internal/private IP addresses (0.0.0.0 is always filtered)"),
	)

	flagSet.CreateGroup("resolver", "Resolver",
		flagSet.StringVarP(&options.QueryType, "type", "rt", "A", "DNS record type to resolve (A, AAAA, CNAME, NS, PTR, MX, TXT, SOA)"),
		flagSet.StringVarP(&options.BatchMode, "batch-mode", "bm", "off", "sendmmsg/recvmmsg batching: off | on | adaptive (Linux)"),
		flagSet.IntVarP(&options.SocketCount, "socket-count", "sc", 0, "UDP sockets per run (0 = scale to cores)"),
		flagSet.IntVar(&options.UDPSize, "udp-size", 0, "EDNS0 UDP payload size (0 = 1232; <512 disables EDNS0)"),
		flagSet.BoolVar(&options.NoRecurse, "norecurse", false, "Send non-recursive queries (RD=0)"),
		flagSet.BoolVar(&options.Sticky, "sticky", false, "Do not rotate resolver on retry"),
		flagSet.BoolVarP(&options.ResolverHealth, "resolver-health", "rhz", false, "De-weight failing resolvers via health scoring"),
		flagSet.BoolVarP(&options.AdaptiveConcurrency, "adaptive-concurrency", "acy", false, "Adapt in-flight concurrency to packet loss"),
		flagSet.BoolVarP(&options.CrossCheck, "cross-check", "cc", false, "Re-verify positive answers on a second resolver"),
		flagSet.BoolVarP(&options.ExtendedInput, "extended-input", "ei", false, "Parse 'name [resolver ...]' input lines"),
		flagSet.BoolVar(&options.NoVerifyIP, "no-verify-ip", false, "Disable reply source-IP verification"),
		flagSet.BoolVar(&options.NoTCPFallback, "no-tcp-fallback", false, "Disable TCP fallback on truncated answers"),
		flagSet.BoolVarP(&options.Iterative, "iterative", "it", false, "Recurse from root servers (no resolver list needed); caches delegations"),
	)

	flagSet.CreateGroup("distributed", "Distributed",
		flagSet.StringVar(&options.Shard, "shard", "", "Process only shard m of n for distributed runs (e.g. 2/8)"),
		flagSet.StringVarP(&options.ResumeFile, "resume", "rs", "", "Checkpoint file for crash-safe stop/resume"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "Show only subdomains in output"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version of shuffledns"),
		flagSet.BoolVar(&options.Verbose, "v", false, "Show Verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "Don't Use colors in output"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	// Read the inputs and configure the logging
	options.configureOutput()

	// Show the user the banner
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("shuffledns", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("shuffledns version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current shuffledns version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}
