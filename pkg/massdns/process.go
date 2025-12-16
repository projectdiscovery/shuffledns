package massdns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/projectdiscovery/shuffledns/pkg/store"
	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
	"github.com/projectdiscovery/utils/batcher"
	fileutil "github.com/projectdiscovery/utils/file"
	ioutil "github.com/projectdiscovery/utils/io"
	"github.com/remeh/sizedwaitgroup"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// runs massdns binary with the specified options
func (instance *Instance) RunWithContext(ctx context.Context) (stdout, stderr string, took time.Duration, err error) {
	start := time.Now()

	// Create temporary file for massdns output
	stdoutFile, err := os.CreateTemp(instance.options.TempDir, "massdns-stdout-")
	if err != nil {
		return "", "", 0, fmt.Errorf("could not create temp file for massdns output: %w", err)
	}
	defer func() {
		_ = stdoutFile.Close()
	}()

	// Handle stderr based on KeepStderr option
	var stderrFile *os.File
	if instance.options.KeepStderr {
		stderrFile, err = os.CreateTemp(instance.options.TempDir, "massdns-stderr-")
		if err != nil {
			return "", "", 0, fmt.Errorf("could not create temp file for massdns stderr: %w", err)
		}
		defer func() {
			_ = stderrFile.Close()
		}()
	}

	// Run the command on a temp file and wait for the output
	args := []string{"-r", instance.options.ResolversFile, "-o", "Snl", "--retry", "REFUSED", "--retry", "SERVFAIL", "-t", "A", instance.options.InputFile, "-s", strconv.Itoa(instance.options.Threads)}
	if instance.options.MassDnsCmd != "" {
		args = append(args, strings.Split(instance.options.MassDnsCmd, " ")...)
	}

	cmd := exec.CommandContext(ctx, instance.options.MassdnsPath, args...)
	cmd.Stdout = stdoutFile

	// Set stderr based on KeepStderr option
	if instance.options.KeepStderr {
		cmd.Stderr = stderrFile
	} else {
		// Discard stderr by sending it to /dev/null
		cmd.Stderr = nil
	}

	err = cmd.Run()

	// Return stderr filename only if it was captured
	stderrFilename := ""
	if instance.options.KeepStderr {
		stderrFilename = stderrFile.Name()
	}

	return stdoutFile.Name(), stderrFilename, time.Since(start), err
}

func (instance *Instance) Run(ctx context.Context) error {
	// Process a created list or the massdns input
	inputFile := instance.options.InputFile
	if instance.options.MassdnsRaw != "" {
		inputFile = instance.options.MassdnsRaw
	}

	// Check for blank input file or non-existent input file
	blank, err := fileutil.IsEmpty(inputFile)
	if err != nil {
		return err
	}
	if blank {
		return errors.New("blank input file specified")
	}

	// Create a store for storing ip metadata
	shstore, err := store.New(instance.options.TempDir)
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer shstore.Close()

	// Check if we need to run massdns
	if instance.options.MassdnsRaw == "" {
		// This case is now handled by the streaming methods in the runner
		// The Run method is only called for raw massdns output processing
		return errors.New("streaming processing should be used for new massdns runs")
	} else { // parse the input file
		gologger.Info().Msgf("Started parsing massdns input\n")
		now := time.Now()
		err = instance.parseMassDNSOutputFile(instance.options.MassdnsRaw, shstore)
		if err != nil {
			return fmt.Errorf("could not parse massdns input: %w", err)
		}
		gologger.Info().Msgf("Massdns input parsing completed in %s\n", time.Since(now))
	}

	if instance.options.AutoExtractRootDomains {
		gologger.Info().Msgf("Started extracting root domains\n")
		now := time.Now()
		err = instance.autoExtractRootDomains(shstore)
		if err != nil {
			return fmt.Errorf("could not extract root domains: %w", err)
		}
		gologger.Info().Msgf("Root domain extraction completed in %s\n", time.Since(now))
	}

	// Perform wildcard filtering only if domain name has been specified
	if len(instance.options.Domains) > 0 {
		gologger.Info().Msgf("Started removing wildcards records\n")
		now := time.Now()
		err = instance.filterWildcards(shstore)
		if err != nil {
			return fmt.Errorf("could not filter wildcards: %w", err)
		}
		gologger.Info().Msgf("Wildcard removal completed in %s\n", time.Since(now))
	}

	gologger.Info().Msgf("Finished enumeration, started writing output\n")

	// Write the final elaborated list out
	now := time.Now()
	err = instance.writeOutput(shstore)
	if err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}
	gologger.Info().Msgf("Output written in %s\n", time.Since(now))
	return nil
}

// runChunk runs massdns on a specific chunk file
func (instance *Instance) runChunk(ctx context.Context, chunkFile string) (stdout, stderr string, took time.Duration, err error) {
	start := time.Now()

	// Create temporary file for massdns output
	stdoutFile, err := os.CreateTemp(instance.options.TempDir, "massdns-chunk-stdout-")
	if err != nil {
		return "", "", 0, fmt.Errorf("could not create temp file for massdns output: %w", err)
	}
	defer func() {
		_ = stdoutFile.Close()
	}()

	// Handle stderr based on KeepStderr option
	var stderrFile *os.File
	if instance.options.KeepStderr {
		stderrFile, err = os.CreateTemp(instance.options.TempDir, "massdns-chunk-stderr-")
		if err != nil {
			return "", "", 0, fmt.Errorf("could not create temp file for massdns stderr: %w", err)
		}
		defer func() {
			_ = stderrFile.Close()
		}()
	}

	// Run the command on the chunk file
	args := []string{"-r", instance.options.ResolversFile, "-o", "Snl", "--retry", "REFUSED", "--retry", "SERVFAIL", "-t", "A", chunkFile, "-s", strconv.Itoa(instance.options.Threads)}
	if instance.options.MassDnsCmd != "" {
		args = append(args, strings.Split(instance.options.MassDnsCmd, " ")...)
	}

	cmd := exec.CommandContext(ctx, instance.options.MassdnsPath, args...)
	cmd.Stdout = stdoutFile

	// Set stderr based on KeepStderr option
	if instance.options.KeepStderr {
		cmd.Stderr = stderrFile
	} else {
		// Discard stderr by sending it to /dev/null
		cmd.Stderr = nil
	}

	err = cmd.Run()

	// Return stderr filename only if it was captured
	stderrFilename := ""
	if instance.options.KeepStderr {
		stderrFilename = stderrFile.Name()
	}

	return stdoutFile.Name(), stderrFilename, time.Since(start), err
}

type item struct {
	ip     string
	domain string
}

func (instance *Instance) parseMassDNSOutputFile(tmpFile string, store *store.Store) error {
	flushToDisk := func(ip string, domains []string) error {
		if err := store.Append(ip, domains...); err != nil {
			return fmt.Errorf("could not update record: %w", err)
		}
		return nil
	}

	bulkWriter := batcher.New[item](
		batcher.WithMaxCapacity[item](10000),
		batcher.WithFlushInterval[item](10*time.Second),
		batcher.WithFlushCallback[item](func(items []item) {
			ipMap := make(map[string][]string)
			for _, item := range items {
				ipMap[item.ip] = append(ipMap[item.ip], item.domain)
			}
			for ip, domains := range ipMap {
				if err := flushToDisk(ip, domains); err != nil {
					gologger.Fatal().Msgf("could not update record: %s", err)
				}
			}
		}),
	)

	bulkWriter.Run()

	err := parser.ParseFile(tmpFile, func(domain string, ips []string) error {
		for _, ip := range ips {
			bulkWriter.Append(item{ip: ip, domain: domain})
		}
		return nil
	})

	bulkWriter.Stop()

	bulkWriter.WaitDone()

	if err != nil {
		return fmt.Errorf("could not parse massdns output: %w", err)
	}

	return nil
}

func (instance *Instance) autoExtractRootDomains(store *store.Store) error {
	candidateRootDomains := make(map[string]struct{})
	store.Iterate(func(ip string, hostnames []string, counter int) {
		for _, hostname := range hostnames {
			rootDomain, err := publicsuffix.Domain(hostname)
			if err != nil {
				continue
			}
			candidateRootDomains[rootDomain] = struct{}{}
		}
	})

	// add the existing ones
	for _, domain := range instance.options.Domains {
		candidateRootDomains[domain] = struct{}{}
	}

	instance.options.Domains = make([]string, 0)
	for item := range candidateRootDomains {
		instance.options.Domains = append(instance.options.Domains, item)
	}

	return nil
}

func (instance *Instance) filterWildcards(st *store.Store) error {
	// Build hostname -> IPs map to avoid redundant DNS queries
	hostnameToIPs := make(map[string][]string)
	hostnameCounters := make(map[string]int)

	st.Iterate(func(ip string, hostnames []string, counter int) {
		for _, hostname := range hostnames {
			hostnameToIPs[hostname] = append(hostnameToIPs[hostname], ip)
			if counter > hostnameCounters[hostname] {
				hostnameCounters[hostname] = counter
			}
		}
	})

	// Start to work in parallel on wildcards
	wildcardWg := sizedwaitgroup.New(instance.options.WildcardsThreads)

	for hostname, ips := range hostnameToIPs {
		// Skip if any IP is already marked as wildcard
		hasWildcardIP := false
		for _, ip := range ips {
			if instance.wildcardStore.Has(ip) {
				hasWildcardIP = true
				break
			}
		}
		if hasWildcardIP {
			continue
		}

		counter := hostnameCounters[hostname]
		// Perform wildcard detection on the hostname if counter >= 5 or strict mode
		if counter >= 5 || instance.options.StrictWildcard {
			wildcardWg.Add()
			go func(hostname string, ips []string) {
				defer wildcardWg.Done()

				gologger.Info().Msgf("Started filtering wildcards for %s (with %d IPs)\n", hostname, len(ips))

				isWildcard, wildcardIPs := instance.wildcardResolver.LookupHost(hostname, ips)
				if len(wildcardIPs) > 0 {
					for ip := range wildcardIPs {
						if err := instance.wildcardStore.Set(ip); err != nil {
							gologger.Error().Msgf("could not set wildcard ip: %s", err)
						}
						gologger.Info().Msgf("Removing wildcard %s\n", ip)
					}
				}

				if isWildcard {
					for _, ip := range ips {
						if err := instance.wildcardStore.Set(ip); err != nil {
							gologger.Error().Msgf("could not set wildcard ip: %s", err)
						}
					}
					gologger.Info().Msgf("Removed wildcard hostname %s with %d IPs\n", hostname, len(ips))
				}

			}(hostname, ips)
		}
	}

	wildcardWg.Wait()

	// Do a second pass as well and remove all the wildcards
	// from the store that we have found so that everything is covered
	allWildcardIPs := instance.wildcardResolver.GetAllWildcardIPs()
	for ip := range allWildcardIPs {
		_ = st.Delete(ip)
	}
	// drop all wildcard from the store
	return instance.wildcardStore.Iterate(func(k string) error {
		return st.Delete(k)
	})
}

func (instance *Instance) writeOutput(store *store.Store) error {
	// Write the unique deduplicated output to the file or stdout
	// depending on what the user has asked.
	var err error
	var output *os.File
	var safeWriter *ioutil.SafeWriter
	var w *bufio.Writer

	if instance.options.OutputFile != "" {
		output, err = os.Create(instance.options.OutputFile)
		if err != nil {
			return fmt.Errorf("could not create massdns output file: %v", err)
		}
		w = bufio.NewWriter(output)
		safeWriter, err = ioutil.NewSafeWriter(w)
		if err != nil {
			return fmt.Errorf("could not create safe writer: %v", err)
		}
	}

	uniqueMap := make(map[string]struct{})

	// write count of resolved hosts
	resolvedCount := 0

	// if trusted resolvers are specified verify the results
	var dnsResolver *dnsx.DNSX
	if len(instance.options.TrustedResolvers) > 0 {
		gologger.Info().Msgf("Trusted resolvers specified, verifying results\n")
		options := dnsx.DefaultOptions
		resolvers, err := wildcards.LoadResolversFromFile(instance.options.TrustedResolvers)
		if err != nil {
			return fmt.Errorf("could not load trusted resolvers: %w", err)
		}
		options.BaseResolvers = resolvers
		dnsResolver, err = dnsx.New(options)
		if err != nil {
			return fmt.Errorf("could not create dns resolver: %w", err)
		}
	}

	swg := sizedwaitgroup.New(instance.options.WildcardsThreads)

	store.Iterate(func(ip string, hostnames []string, counter int) {
		for _, hostname := range hostnames {
			// Skip if we already printed this subdomain once
			if _, ok := uniqueMap[hostname]; ok {
				continue
			}
			uniqueMap[hostname] = struct{}{}

			swg.Add()
			go func(hostname string) {
				defer swg.Done()

				if dnsResolver != nil {
					if resp, err := dnsResolver.QueryOne(hostname); err != nil || len(resp.A) == 0 {
						gologger.Info().Msgf("not resolved with trusted resolver - skipping: %s", hostname)
						return
					} else {
						// perform a last check on wildcards ip in case some hosts sneaked due to bad resolvers
						for _, ip := range resp.A {
							if instance.wildcardStore.Has(ip) {
								gologger.Info().Msgf("resolved with trusted resolver but is a wildcard - skipping: %s", hostname)
								return
							}
						}

						gologger.Info().Msgf("resolved with trusted resolver: %s", hostname)

						if instance.options.OnResult != nil {
							instance.options.OnResult(resp)
						}
					}
				}

				var buffer strings.Builder

				if instance.options.Json {
					hostnameJson, err := json.Marshal(map[string]interface{}{"hostname": hostname})
					if err != nil {
						gologger.Error().Msgf("could not marshal output as json: %v", err)
					}

					buffer.WriteString(string(hostnameJson))
					buffer.WriteString("\n")
				} else {
					buffer.WriteString(hostname)
					buffer.WriteString("\n")
				}

				data := buffer.String()

				if output != nil {
					_, _ = safeWriter.Write([]byte(data))
				}
				gologger.Silent().Msgf("%s", data)
				resolvedCount++
			}(hostname)
		}
	})

	swg.Wait()

	gologger.Info().Msgf("Total resolved: %d\n", resolvedCount)

	// Close the files and return
	if output != nil {
		_ = w.Flush()
		_ = output.Close()
	}
	return nil
}

// ProcessDomainStreaming processes domain bruteforce using streaming with batcher
func (instance *Instance) ProcessDomainStreaming(ctx context.Context, wordlistFile *os.File) error {
	// Create a store for storing ip metadata
	shstore, err := store.New(instance.options.TempDir)
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer shstore.Close()

	// Create batcher for streaming permutations
	chunkNum := 0
	permutationCount := 0

	bulkWriter := batcher.New[string](
		batcher.WithMaxCapacity[string](instance.options.BatchSize),
		batcher.WithFlushInterval[string](10*time.Second),
		batcher.WithFlushCallback[string](func(permutations []string) {
			chunkNum++
			if len(permutations) == 0 {
				return
			}

			gologger.Info().Msgf("Processing chunk %d (%d permutations, total: %d)\n",
				chunkNum, len(permutations), permutationCount)

			// Create temporary chunk file
			chunkFile, err := os.CreateTemp(instance.options.TempDir, fmt.Sprintf("chunk-%d-", chunkNum))
			if err != nil {
				gologger.Error().Msgf("Could not create chunk file: %s\n", err)
				return
			}

			// Write permutations to chunk file
			writer := bufio.NewWriter(chunkFile)
			for _, permutation := range permutations {
				_, err := writer.WriteString(permutation + "\n")
				if err != nil {
					gologger.Error().Msgf("Could not write to chunk file: %s\n", err)
					_ = chunkFile.Close()
					_ = os.Remove(chunkFile.Name())
					return
				}
			}
			_ = writer.Flush()
			_ = chunkFile.Close()

			// Run massdns on this chunk
			chunkStart := time.Now()
			stdoutFile, stderrFile, took, err := instance.runChunk(ctx, chunkFile.Name())
			if err != nil {
				gologger.Error().Msgf("Could not execute massdns on chunk %d: %s\n", chunkNum, err)
				_ = os.Remove(chunkFile.Name())
				return
			}

			gologger.Info().Msgf("Chunk %d massdns execution took %s\n", chunkNum, took)

			// Parse the chunk output immediately
			parseStart := time.Now()
			err = instance.parseMassDNSOutputFile(stdoutFile, shstore)
			if err != nil {
				gologger.Error().Msgf("Could not parse massdns output for chunk %d: %s\n", chunkNum, err)
				_ = os.Remove(chunkFile.Name())
				_ = os.Remove(stdoutFile)
				if stderrFile != "" {
					_ = os.Remove(stderrFile)
				}
				return
			}

			gologger.Info().Msgf("Chunk %d parsing completed in %s\n", chunkNum, time.Since(parseStart))

			// Clean up chunk files immediately
			_ = os.Remove(chunkFile.Name())
			_ = os.Remove(stdoutFile)
			if stderrFile != "" {
				_ = os.Remove(stderrFile)
			}

			gologger.Info().Msgf("Chunk %d completed in %s\n", chunkNum, time.Since(chunkStart))
		}),
	)

	bulkWriter.Run()

	// Read wordlist and generate permutations on-the-fly
	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		// RFC4343 - case insensitive domain
		text := strings.ToLower(scanner.Text())
		if text == "" {
			continue
		}

		// Generate permutations for each domain
		for _, domain := range instance.options.Domains {
			permutation := text + "." + domain
			bulkWriter.Append(permutation)
			permutationCount++
		}
	}

	// Stop the batcher and wait for completion
	bulkWriter.Stop()
	bulkWriter.WaitDone()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading wordlist: %w", err)
	}

	gologger.Info().Msgf("Total permutations generated: %d\n", permutationCount)

	// Perform post-processing steps
	if instance.options.AutoExtractRootDomains {
		gologger.Info().Msgf("Started extracting root domains\n")
		now := time.Now()
		err = instance.autoExtractRootDomains(shstore)
		if err != nil {
			return fmt.Errorf("could not extract root domains: %w", err)
		}
		gologger.Info().Msgf("Root domain extraction completed in %s\n", time.Since(now))
	}

	// Perform wildcard filtering only if domain name has been specified
	if len(instance.options.Domains) > 0 {
		gologger.Info().Msgf("Started removing wildcards records\n")
		now := time.Now()
		err = instance.filterWildcards(shstore)
		if err != nil {
			return fmt.Errorf("could not filter wildcards: %w", err)
		}
		gologger.Info().Msgf("Wildcard removal completed in %s\n", time.Since(now))
	}

	gologger.Info().Msgf("Finished enumeration, started writing output\n")

	// Write the final elaborated list out
	now := time.Now()
	err = instance.writeOutput(shstore)
	if err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}
	gologger.Info().Msgf("Output written in %s\n", time.Since(now))

	return nil
}

// ProcessSubdomainsStreaming processes subdomain list using streaming with batcher
func (instance *Instance) ProcessSubdomainsStreaming(ctx context.Context, subdomainReader io.Reader) error {
	// Create a store for storing ip metadata
	shstore, err := store.New(instance.options.TempDir)
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer shstore.Close()

	// Create batcher for streaming subdomains
	chunkNum := 0
	subdomainCount := 0

	bulkWriter := batcher.New[string](
		batcher.WithMaxCapacity[string](instance.options.BatchSize),
		batcher.WithFlushInterval[string](10*time.Second),
		batcher.WithFlushCallback[string](func(subdomains []string) {
			chunkNum++
			if len(subdomains) == 0 {
				return
			}

			gologger.Info().Msgf("Processing chunk %d (%d subdomains, total: %d)\n",
				chunkNum, len(subdomains), subdomainCount)

			// Create temporary chunk file
			chunkFile, err := os.CreateTemp(instance.options.TempDir, fmt.Sprintf("chunk-%d-", chunkNum))
			if err != nil {
				gologger.Error().Msgf("Could not create chunk file: %s\n", err)
				return
			}

			// Write subdomains to chunk file
			writer := bufio.NewWriter(chunkFile)
			for _, subdomain := range subdomains {
				_, err := writer.WriteString(subdomain + "\n")
				if err != nil {
					gologger.Error().Msgf("Could not write to chunk file: %s\n", err)
					_ = chunkFile.Close()
					_ = os.Remove(chunkFile.Name())
					return
				}
			}
			_ = writer.Flush()
			_ = chunkFile.Close()

			// Run massdns on this chunk
			chunkStart := time.Now()
			stdoutFile, stderrFile, took, err := instance.runChunk(ctx, chunkFile.Name())
			if err != nil {
				gologger.Error().Msgf("Could not execute massdns on chunk %d: %s\n", chunkNum, err)
				_ = os.Remove(chunkFile.Name())
				return
			}

			gologger.Info().Msgf("Chunk %d massdns execution took %s\n", chunkNum, took)

			// Parse the chunk output immediately
			parseStart := time.Now()
			err = instance.parseMassDNSOutputFile(stdoutFile, shstore)
			if err != nil {
				gologger.Error().Msgf("Could not parse massdns output for chunk %d: %s\n", chunkNum, err)
				_ = os.Remove(chunkFile.Name())
				_ = os.Remove(stdoutFile)
				if stderrFile != "" {
					_ = os.Remove(stderrFile)
				}
				return
			}

			gologger.Info().Msgf("Chunk %d parsing completed in %s\n", chunkNum, time.Since(parseStart))

			// Clean up chunk files immediately
			_ = os.Remove(chunkFile.Name())
			_ = os.Remove(stdoutFile)
			if stderrFile != "" {
				_ = os.Remove(stderrFile)
			}

			gologger.Info().Msgf("Chunk %d completed in %s\n", chunkNum, time.Since(chunkStart))
		}),
	)

	bulkWriter.Run()

	// Read subdomains and stream them to batcher
	scanner := bufio.NewScanner(subdomainReader)
	for scanner.Scan() {
		// RFC4343 - case insensitive domain
		subdomain := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if subdomain == "" {
			continue
		}

		bulkWriter.Append(subdomain)
		subdomainCount++
	}

	// Stop the batcher and wait for completion
	bulkWriter.Stop()
	bulkWriter.WaitDone()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading subdomains: %w", err)
	}

	gologger.Info().Msgf("Total subdomains processed: %d\n", subdomainCount)

	// Perform post-processing steps
	if instance.options.AutoExtractRootDomains {
		gologger.Info().Msgf("Started extracting root domains\n")
		now := time.Now()
		err = instance.autoExtractRootDomains(shstore)
		if err != nil {
			return fmt.Errorf("could not extract root domains: %w", err)
		}
		gologger.Info().Msgf("Root domain extraction completed in %s\n", time.Since(now))
	}

	// Perform wildcard filtering only if domain name has been specified
	if len(instance.options.Domains) > 0 {
		gologger.Info().Msgf("Started removing wildcards records\n")
		now := time.Now()
		err = instance.filterWildcards(shstore)
		if err != nil {
			return fmt.Errorf("could not filter wildcards: %w", err)
		}
		gologger.Info().Msgf("Wildcard removal completed in %s\n", time.Since(now))
	}

	gologger.Info().Msgf("Finished enumeration, started writing output\n")

	// Write the final elaborated list out
	now := time.Now()
	err = instance.writeOutput(shstore)
	if err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}
	gologger.Info().Msgf("Output written in %s\n", time.Since(now))

	return nil
}
