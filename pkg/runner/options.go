package runner

import (
	"os"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

// Options contains the configuration options for tuning
// the active dns resolving process.
type Options struct {
	Directory          string              // Directory is a directory for temporary data
	Domains            goflags.StringSlice // Domains is the list of domains to find subdomains
	SubdomainsList     string              // SubdomainsList is the file containing list of hosts to resolve
	ResolversFile      string              // ResolversFile is the file containing resolvers to use for enumeration
	TrustedResolvers   string              // TrustedResolvers is the file containing trusted resolvers
	Wordlist           string              // Wordlist is a wordlist to use for enumeration
	MassdnsPath        string              // MassdnsPath contains the path to massdns binary
	Output             string              // Output is the file to write found subdomains to.
	Json               bool                // Json is the format for making output as ndjson
	Silent             bool                // Silent suppresses any extra text and only writes found host:port to screen
	Version            bool                // Version specifies if we should just show version and exit
	Retries            int                 // Retries is the number of retries for dns enumeration
	Verbose            bool                // Verbose flag indicates whether to show verbose output or not
	NoColor            bool                // No-Color disables the colored output
	Threads            int                 // Thread controls the number of parallel host to enumerate
	MassdnsRaw         string              // MassdnsRaw perform wildcards filtering from an existing massdns output file
	WildcardThreads    int                 // WildcardsThreads controls the number of parallel host to check for wildcard
	StrictWildcard     bool                // StrictWildcard flag indicates whether wildcard check has to be performed on each found subdomains
	WildcardOutputFile string              // StrictWildcard flag indicates whether wildcard check has to be performed on each found subdomains
	MassDnsCmd         string              // Supports massdns flags(example -i)
	DisableUpdateCheck bool                // DisableUpdateCheck disable automatic update check
	Mode               string

	OnResult func(ip string, hostnames []string)
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`shuffleDNS is a wrapper around massdns written in go that allows you to enumerate valid subdomains using active bruteforce as well as resolve subdomains with wildcard handling and easy input-output support.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Domains, "domain", "d", nil, "Domain to find or resolve subdomains for", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.SubdomainsList, "list", "l", "", "File containing list of subdomains to resolve"),
		flagSet.StringVarP(&options.Wordlist, "wordlist", "w", "", "File containing words to bruteforce for domain"),
		flagSet.StringVarP(&options.ResolversFile, "resolver", "r", "", "File containing list of resolvers for enumeration"),
		flagSet.StringVarP(&options.TrustedResolvers, "trusted-resolver", "tr", "", "File containing list of trusted resolvers"),
		flagSet.StringVarP(&options.MassdnsRaw, "raw-input", "ri", "", "Validate raw full massdns output"),
		flagSet.StringVar(&options.Mode, "mode", "", "Execution mode (bruteforce, resolve)"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVar(&options.Threads, "t", 10000, "Number of concurrent massdns resolves"),
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
		flagSet.StringVarP(&options.MassdnsPath, "massdns", "m", "", "Path to the massdns binary"),
		flagSet.StringVarP(&options.MassDnsCmd, "massdns-cmd", "mcmd", "", "Optional massdns commands to run (example '-i 10')"),
		flagSet.StringVar(&options.Directory, "directory", "", "Temporary directory for enumeration"),
	)

	flagSet.CreateGroup("optimizations", "Optimizations",
		flagSet.IntVar(&options.Retries, "retries", 5, "Number of retries for dns enumeration"),
		flagSet.BoolVarP(&options.StrictWildcard, "strict-wildcard", "sw", false, "Perform wildcard check on all found subdomains"),
		flagSet.IntVar(&options.WildcardThreads, "wt", 25, "Number of concurrent wildcard checks"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "Show only subdomains in output"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version of shuffledns"),
		flagSet.BoolVar(&options.Verbose, "v", false, "Show Verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "Don't Use colors in output"),
	)

	_ = flagSet.Parse()

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
