package runner

import (
	"context"
	"errors"
	"fmt"
	"os"

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

// massdnsOptions builds the massdns.Options from the runner options. Keeping it
// in one place avoids drift between the bruteforce, resolve and raw-input paths
// and makes the embeddable surface easy to reason about.
func (r *Runner) massdnsOptions() massdns.Options {
	return massdns.Options{
		Domains:                r.options.Domains,
		AutoExtractRootDomains: r.options.AutoExtractRootDomains,
		Retries:                r.options.Retries,
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
		FilterInternalIPs:      r.options.FilterInternalIPs,
		QueryType:              r.options.QueryType,
		BatchMode:              r.options.BatchMode,
		SocketCount:            r.options.SocketCount,
		UDPSize:                r.options.UDPSize,
		QPS:                    r.options.QPS,
		NoRecurse:              r.options.NoRecurse,
		Sticky:                 r.options.Sticky,
		ResolverHealth:         r.options.ResolverHealth,
		AdaptiveConcurrency:    r.options.AdaptiveConcurrency,
		CrossCheck:             r.options.CrossCheck,
		ExtendedInput:          r.options.ExtendedInput,
		NoVerifyIP:             r.options.NoVerifyIP,
		NoTCPFallback:          r.options.NoTCPFallback,
		Iterative:              r.options.Iterative,
		Shard:                  r.options.Shard,
		ResumeFile:             r.options.ResumeFile,
		OnResult:               r.options.OnResult,
	}
}

// RunEnumeration sets up the input layer for giving input to the native
// resolver and runs the actual enumeration. It returns an error so the process
// is fully embeddable (the CLI is responsible for logging/exit codes).
func (r *Runner) RunEnumeration() error {
	switch {
	case r.options.MassdnsRaw != "":
		return r.processExistingOutput()
	case r.options.Wordlist != "":
		return r.processDomain()
	case r.options.SubdomainsList != "" || fileutil.HasStdin():
		return r.processSubdomains()
	default:
		return errors.New("no input provided: set a wordlist, a subdomains list, stdin, or raw massdns input")
	}
}

// dumpWildcards writes the discovered wildcard IPs when requested.
func (r *Runner) dumpWildcards(instance *massdns.Instance) {
	if r.options.WildcardOutputFile != "" {
		_ = instance.DumpWildcardsToFile(r.options.WildcardOutputFile)
	}
}

// processDomain processes the bruteforce for a domain using a wordlist
func (r *Runner) processDomain() error {
	inputFile, err := os.Open(r.options.Wordlist)
	if err != nil {
		return fmt.Errorf("could not read bruteforce wordlist (%s): %w", r.options.Wordlist, err)
	}
	defer func() {
		_ = inputFile.Close()
	}()

	gologger.Info().Msgf("Started generating bruteforce permutation with streaming processing\n")

	instance, err := massdns.New(r.massdnsOptions())
	if err != nil {
		return fmt.Errorf("could not create massdns client: %w", err)
	}

	if err := instance.ProcessDomainStreaming(context.Background(), inputFile); err != nil {
		return fmt.Errorf("could not process domain with streaming: %w", err)
	}

	r.dumpWildcards(instance)
	gologger.Info().Msgf("Finished resolving.\n")
	return nil
}

// processSubdomains processes the resolving for a list of subdomains
func (r *Runner) processSubdomains() error {
	instance, err := massdns.New(r.massdnsOptions())
	if err != nil {
		return fmt.Errorf("could not create massdns client: %w", err)
	}

	if fileutil.HasStdin() && r.options.SubdomainsList == "" {
		gologger.Info().Msgf("Processing subdomains from stdin with streaming\n")
		if err := instance.ProcessSubdomainsStreaming(context.Background(), os.Stdin); err != nil {
			return fmt.Errorf("could not process subdomains from stdin: %w", err)
		}
	} else {
		subdomainFile, err := os.Open(r.options.SubdomainsList)
		if err != nil {
			return fmt.Errorf("could not open subdomain list (%s): %w", r.options.SubdomainsList, err)
		}
		defer func() {
			_ = subdomainFile.Close()
		}()

		gologger.Info().Msgf("Processing subdomains from file with streaming\n")
		if err := instance.ProcessSubdomainsStreaming(context.Background(), subdomainFile); err != nil {
			return fmt.Errorf("could not process subdomains from file: %w", err)
		}
	}

	r.dumpWildcards(instance)
	gologger.Info().Msgf("Finished resolving.\n")
	return nil
}

// processExistingOutput processes existing massdns output for wildcard filtering
func (r *Runner) processExistingOutput() error {
	instance, err := massdns.New(r.massdnsOptions())
	if err != nil {
		return fmt.Errorf("could not create massdns client: %w", err)
	}

	if err := instance.Run(context.Background()); err != nil {
		return fmt.Errorf("could not process existing massdns output: %w", err)
	}

	r.dumpWildcards(instance)
	gologger.Info().Msgf("Finished processing existing output.\n")
	return nil
}
