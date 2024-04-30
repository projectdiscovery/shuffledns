package runner

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/massdns"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/rs/xid"
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
	os.RemoveAll(r.tempDir)
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
	// Handle a domain to bruteforce with wordlist
	if r.options.Wordlist != "" {
		r.processDomain()
		return
	}

	// Handle only wildcard filtering
	if r.options.MassdnsRaw != "" {
		r.processSubdomains()
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
	resolveFile := filepath.Join(r.tempDir, xid.New().String())
	file, err := os.Create(resolveFile)
	if err != nil {
		gologger.Error().Msgf("Could not create bruteforce list (%s): %s\n", r.tempDir, err)
		return
	}
	writer := bufio.NewWriter(file)

	// Read the input wordlist for bruteforce generation
	inputFile, err := os.Open(r.options.Wordlist)
	if err != nil {
		gologger.Error().Msgf("Could not read bruteforce wordlist (%s): %s\n", r.options.Wordlist, err)
		file.Close()
		return
	}

	gologger.Info().Msgf("Started generating bruteforce permutation\n")

	now := time.Now()
	// Create permutation for domain with wordlist
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		// RFC4343 - case insensitive domain
		text := strings.ToLower(scanner.Text())
		if text == "" {
			continue
		}
		_, _ = writer.WriteString(text + "." + r.options.Domain + "\n")
	}
	writer.Flush()
	inputFile.Close()
	file.Close()

	gologger.Info().Msgf("Generating permutations took %s\n", time.Since(now))

	// Run the actual massdns enumeration process
	r.runMassdns(resolveFile)
}

// processSubdomain processes the resolving for a list of subdomains
func (r *Runner) processSubdomains() {
	var resolveFile string

	// If there is stdin, write the resolution list to the file
	if fileutil.HasStdin() && r.options.SubdomainsList == "" {
		file, err := os.CreateTemp(r.tempDir, "massdns-stdin-")
		if err != nil {
			gologger.Error().Msgf("Could not create resolution list (%s): %s\n", r.tempDir, err)
			return
		}
		_, _ = io.Copy(file, os.Stdin)
		file.Close()
		resolveFile = file.Name()
	} else {
		// Use the file if user has provided one
		resolveFile = r.options.SubdomainsList
	}

	// Run the actual massdns enumeration process
	r.runMassdns(resolveFile)
}

// runMassdns runs the massdns tool on the list of inputs
func (r *Runner) runMassdns(inputFile string) {
	massdns, err := massdns.New(massdns.Options{
		Domain:             r.options.Domain,
		Retries:            r.options.Retries,
		MassdnsPath:        r.options.MassdnsPath,
		Threads:            r.options.Threads,
		WildcardsThreads:   r.options.WildcardThreads,
		InputFile:          inputFile,
		ResolversFile:      r.options.ResolversFile,
		TempDir:            r.tempDir,
		OutputFile:         r.options.Output,
		Json:               r.options.Json,
		MassdnsRaw:         r.options.MassdnsRaw,
		StrictWildcard:     r.options.StrictWildcard,
		WildcardOutputFile: r.options.WildcardOutputFile,
		MassDnsCmd:         r.options.MassDnsCmd,
		OnResult:           r.options.OnResult,
	})
	if err != nil {
		gologger.Error().Msgf("Could not create massdns client: %s\n", err)
		return
	}

	err = massdns.Run(context.Background())
	if err != nil {
		gologger.Error().Msgf("Could not run massdns: %s\n", err)
	}

	if r.options.WildcardOutputFile != "" {
		_ = massdns.DumpWildcardsToFile(r.options.WildcardOutputFile)
	}

	gologger.Info().Msgf("Finished resolving.\n")
}
