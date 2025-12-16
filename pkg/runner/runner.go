package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/massdns"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	tempDir string
	options *Options
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	// Setup the massdns binary path if none was give.
	// If no valid path found, return an error
	if options.MassdnsPath == "" {
		options.MassdnsPath = runner.findBinary()
		if options.MassdnsPath == "" {
			return nil, errors.New("could not find massdns binary")
		}
		gologger.Debug().Msgf("Discovered massdns binary at %s\n", options.MassdnsPath)
	}

	// Create a temporary directory that will be removed at the end
	// of enumeration process.
	dir, err := os.MkdirTemp(options.Directory, "shuffledns-*")
	if err != nil {
		return nil, err
	}
	runner.tempDir = dir

	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	_ = os.RemoveAll(r.tempDir)
}

// findBinary searches for massdns binary in various pre-defined paths
// only linux and macos paths are supported rn
func (r *Runner) findBinary() string {
	otherCommonLocations := []string{
		"/usr/bin/massdns",
		"/usr/local/bin/massdns",
		"/data/data/com.termux/files/usr/bin/massdns",
	}

	for _, file := range otherCommonLocations {
		if fileutil.FileExists(file) {
			return file
		}
	}

	file, err := exec.LookPath("massdns")
	if err != nil {
		return ""
	}

	return file
}

// RunEnumeration sets up the input layer for giving input to massdns
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	// Handle only wildcard filtering on existing massdns output
	if r.options.MassdnsRaw != "" {
		r.processExistingOutput()
		return
	}

	// Handle a domain to bruteforce with wordlist
	if r.options.Wordlist != "" {
		r.processDomain()
		return
	}

	// Handle a list of subdomains to resolve
	if r.options.SubdomainsList != "" || fileutil.HasStdin() {
		r.processSubdomains()
		return
	}
}

// processDomain processes the bruteforce for a domain using a wordlist
func (r *Runner) processDomain() {
	// Read the input wordlist for bruteforce generation
	inputFile, err := os.Open(r.options.Wordlist)
	if err != nil {
		gologger.Error().Msgf("Could not read bruteforce wordlist (%s): %s\n", r.options.Wordlist, err)
		return
	}
	defer func() {
		_ = inputFile.Close()
	}()

	gologger.Info().Msgf("Started generating bruteforce permutation with streaming processing\n")

	// Create massdns instance for processing chunks
	massdns, err := massdns.New(massdns.Options{
		Domains:                r.options.Domains,
		AutoExtractRootDomains: r.options.AutoExtractRootDomains,
		Retries:                r.options.Retries,
		MassdnsPath:            r.options.MassdnsPath,
		Threads:                r.options.Threads,
		WildcardsThreads:       r.options.WildcardThreads,
		ResolversFile:          r.options.ResolversFile,
		TrustedResolvers:       r.options.TrustedResolvers,
		TempDir:                r.tempDir,
		OutputFile:             r.options.Output,
		Json:                   r.options.Json,
		MassdnsRaw:             r.options.MassdnsRaw,
		StrictWildcard:         r.options.StrictWildcard,
		WildcardOutputFile:     r.options.WildcardOutputFile,
		MassDnsCmd:             r.options.MassDnsCmd,
		KeepStderr:             r.options.KeepStderr,
		BatchSize:              r.options.BatchSize,
		FilterInternalIPs:      r.options.FilterInternalIPs,
		OnResult:               r.options.OnResult,
	})
	if err != nil {
		gologger.Error().Msgf("Could not create massdns client: %s\n", err)
		return
	}

	// Use streaming processing with batcher
	err = massdns.ProcessDomainStreaming(context.Background(), inputFile)
	if err != nil {
		gologger.Error().Msgf("Could not process domain with streaming: %s\n", err)
		return
	}

	if r.options.WildcardOutputFile != "" {
		_ = massdns.DumpWildcardsToFile(r.options.WildcardOutputFile)
	}

	gologger.Info().Msgf("Finished resolving.\n")
}

// processSubdomain processes the resolving for a list of subdomains
func (r *Runner) processSubdomains() {
	// Create massdns instance for processing chunks
	massdns, err := massdns.New(massdns.Options{
		Domains:                r.options.Domains,
		AutoExtractRootDomains: r.options.AutoExtractRootDomains,
		Retries:                r.options.Retries,
		MassdnsPath:            r.options.MassdnsPath,
		Threads:                r.options.Threads,
		WildcardsThreads:       r.options.WildcardThreads,
		ResolversFile:          r.options.ResolversFile,
		TrustedResolvers:       r.options.TrustedResolvers,
		TempDir:                r.tempDir,
		OutputFile:             r.options.Output,
		Json:                   r.options.Json,
		MassdnsRaw:             r.options.MassdnsRaw,
		StrictWildcard:         r.options.StrictWildcard,
		WildcardOutputFile:     r.options.WildcardOutputFile,
		MassDnsCmd:             r.options.MassDnsCmd,
		KeepStderr:             r.options.KeepStderr,
		BatchSize:              r.options.BatchSize,
		FilterInternalIPs:      r.options.FilterInternalIPs,
		OnResult:               r.options.OnResult,
	})
	if err != nil {
		gologger.Error().Msgf("Could not create massdns client: %s\n", err)
		return
	}

	// Handle stdin or file input
	if fileutil.HasStdin() && r.options.SubdomainsList == "" {
		// Use streaming processing for stdin
		gologger.Info().Msgf("Processing subdomains from stdin with streaming\n")
		err = massdns.ProcessSubdomainsStreaming(context.Background(), os.Stdin)
		if err != nil {
			gologger.Error().Msgf("Could not process subdomains with streaming: %s\n", err)
			return
		}
	} else {
		// Use streaming processing for file
		subdomainFile, err := os.Open(r.options.SubdomainsList)
		if err != nil {
			gologger.Error().Msgf("Could not open subdomain list (%s): %s\n", r.options.SubdomainsList, err)
			return
		}
		defer func() {
			_ = subdomainFile.Close()
		}()

		gologger.Info().Msgf("Processing subdomains from file with streaming\n")
		err = massdns.ProcessSubdomainsStreaming(context.Background(), subdomainFile)
		if err != nil {
			gologger.Error().Msgf("Could not process subdomains with streaming from file: %s\n", err)
			return
		}
	}

	if r.options.WildcardOutputFile != "" {
		_ = massdns.DumpWildcardsToFile(r.options.WildcardOutputFile)
	}

	gologger.Info().Msgf("Finished resolving.\n")
}

// processExistingOutput processes existing massdns output for wildcard filtering
func (r *Runner) processExistingOutput() {
	massdns, err := massdns.New(massdns.Options{
		Domains:                r.options.Domains,
		AutoExtractRootDomains: r.options.AutoExtractRootDomains,
		Retries:                r.options.Retries,
		MassdnsPath:            r.options.MassdnsPath,
		Threads:                r.options.Threads,
		WildcardsThreads:       r.options.WildcardThreads,
		ResolversFile:          r.options.ResolversFile,
		TrustedResolvers:       r.options.TrustedResolvers,
		TempDir:                r.tempDir,
		OutputFile:             r.options.Output,
		Json:                   r.options.Json,
		MassdnsRaw:             r.options.MassdnsRaw,
		StrictWildcard:         r.options.StrictWildcard,
		WildcardOutputFile:     r.options.WildcardOutputFile,
		MassDnsCmd:             r.options.MassDnsCmd,
		KeepStderr:             r.options.KeepStderr,
		BatchSize:              r.options.BatchSize,
		FilterInternalIPs:      r.options.FilterInternalIPs,
		OnResult:               r.options.OnResult,
	})
	if err != nil {
		gologger.Error().Msgf("Could not create massdns client: %s\n", err)
		return
	}

	err = massdns.Run(context.Background())
	if err != nil {
		gologger.Error().Msgf("Could not process existing massdns output: %s\n", err)
		return
	}

	if r.options.WildcardOutputFile != "" {
		_ = massdns.DumpWildcardsToFile(r.options.WildcardOutputFile)
	}

	gologger.Info().Msgf("Finished processing existing output.\n")
}
