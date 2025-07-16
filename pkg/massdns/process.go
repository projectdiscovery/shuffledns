package massdns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	folderutil "github.com/projectdiscovery/utils/folder"
	ioutil "github.com/projectdiscovery/utils/io"
	stringsutil "github.com/projectdiscovery/utils/strings"
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

	log.Fatalf("flag: %s %s", instance.options.MassdnsPath, strings.Join(args, " "))
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
		if len(instance.options.Domains) > 0 {
			gologger.Info().Msgf("Executing massdns on %s\n", strings.Join(instance.options.Domains, ", "))
		} else {
			gologger.Info().Msgf("Executing massdns\n")
		}

		// Use incremental processing for large inputs
		if instance.options.BatchSize > 0 {
			gologger.Info().Msgf("Using incremental processing with batch size: %d\n", instance.options.BatchSize)
			err = instance.processIncremental(ctx, inputFile, shstore)
		} else {
			// Fallback to original single massdns run
			gologger.Info().Msgf("Using single massdns run\n")
			err = instance.processSingle(ctx, shstore)
		}

		if err != nil {
			return fmt.Errorf("could not execute massdns: %w", err)
		}
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

// processSingle runs massdns on the entire input file (original behavior)
func (instance *Instance) processSingle(ctx context.Context, shstore *store.Store) error {
	// Create a temporary file for the massdns output
	gologger.Info().Msgf("using massdns output directory: %s\n", instance.options.TempDir)
	stdoutFile, stderrFile, took, err := instance.RunWithContext(ctx)
	gologger.Info().Msgf("massdns output file: %s\n", stdoutFile)
	if stderrFile != "" {
		gologger.Info().Msgf("massdns error file: %s\n", stderrFile)
	} else {
		gologger.Info().Msgf("massdns stderr discarded (KeepStderr=false)\n")
	}
	if err != nil {
		return fmt.Errorf("could not execute massdns: %s", err)
	}

	gologger.Info().Msgf("Massdns execution took %s\n", took)

	gologger.Info().Msgf("Started parsing massdns output\n")

	now := time.Now()

	err = instance.parseMassDNSOutputDir(instance.options.TempDir, shstore)
	if err != nil {
		return fmt.Errorf("could not parse massdns output: %w", err)
	}

	gologger.Info().Msgf("Massdns output parsing completed in %s\n", time.Since(now))
	return nil
}

// processIncremental processes input in chunks for better memory and disk usage
func (instance *Instance) processIncremental(ctx context.Context, inputFile string, shstore *store.Store) error {
	// Count total lines to estimate progress
	totalLines, err := instance.countLines(inputFile)
	if err != nil {
		return fmt.Errorf("could not count input lines: %w", err)
	}

	gologger.Info().Msgf("Total input lines: %d\n", totalLines)

	// Create chunks and process them sequentially
	chunkNum := 0
	processedLines := 0

	for {
		chunkNum++
		chunkFile, linesInChunk, err := instance.createChunk(inputFile, chunkNum, processedLines)
		if err != nil {
			return fmt.Errorf("could not create chunk %d: %w", chunkNum, err)
		}

		// If no lines in chunk, we're done
		if linesInChunk == 0 {
			break
		}

		gologger.Info().Msgf("Processing chunk %d (%d lines, %.1f%% complete)\n",
			chunkNum, linesInChunk, float64(processedLines+linesInChunk)/float64(totalLines)*100)

		// Run massdns on this chunk
		chunkStart := time.Now()
		stdoutFile, stderrFile, took, err := instance.runChunk(ctx, chunkFile)
		if err != nil {
			// Clean up chunk file even on error
			_ = os.Remove(chunkFile)
			return fmt.Errorf("could not execute massdns on chunk %d: %w", chunkNum, err)
		}

		gologger.Info().Msgf("Chunk %d massdns execution took %s\n", chunkNum, took)

		// Parse the chunk output immediately
		parseStart := time.Now()
		err = instance.parseMassDNSOutputFile(stdoutFile, shstore)
		if err != nil {
			// Clean up files even on error
			_ = os.Remove(chunkFile)
			_ = os.Remove(stdoutFile)
			if stderrFile != "" {
				_ = os.Remove(stderrFile)
			}
			return fmt.Errorf("could not parse massdns output for chunk %d: %w", chunkNum, err)
		}

		gologger.Info().Msgf("Chunk %d parsing completed in %s\n", chunkNum, time.Since(parseStart))

		// Clean up chunk files immediately
		_ = os.Remove(chunkFile)
		_ = os.Remove(stdoutFile)
		if stderrFile != "" {
			_ = os.Remove(stderrFile)
		}

		processedLines += linesInChunk
		gologger.Info().Msgf("Chunk %d completed in %s\n", chunkNum, time.Since(chunkStart))
	}

	gologger.Info().Msgf("All chunks processed successfully (%d total chunks)\n", chunkNum-1)
	return nil
}

// countLines counts the number of lines in a file
func (instance *Instance) countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

// createChunk creates a chunk file with the specified number of lines
func (instance *Instance) createChunk(inputFile string, chunkNum, startLine int) (string, int, error) {
	// Create chunk file
	chunkFile, err := os.CreateTemp(instance.options.TempDir, fmt.Sprintf("chunk-%d-", chunkNum))
	if err != nil {
		return "", 0, fmt.Errorf("could not create chunk file: %w", err)
	}
	defer chunkFile.Close()

	// Open input file
	input, err := os.Open(inputFile)
	if err != nil {
		_ = os.Remove(chunkFile.Name())
		return "", 0, fmt.Errorf("could not open input file: %w", err)
	}
	defer input.Close()

	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(chunkFile)

	// Skip to start line
	for i := 0; i < startLine; i++ {
		if !scanner.Scan() {
			break
		}
	}

	// Write chunk lines
	linesInChunk := 0
	for i := 0; i < instance.options.BatchSize && scanner.Scan(); i++ {
		_, err := writer.WriteString(scanner.Text() + "\n")
		if err != nil {
			_ = os.Remove(chunkFile.Name())
			return "", 0, fmt.Errorf("could not write to chunk file: %w", err)
		}
		linesInChunk++
	}

	if err := writer.Flush(); err != nil {
		_ = os.Remove(chunkFile.Name())
		return "", 0, fmt.Errorf("could not flush chunk file: %w", err)
	}

	return chunkFile.Name(), linesInChunk, nil
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

func (instance *Instance) parseMassDNSOutputDir(tmpDir string, store *store.Store) error {
	tmpFiles, err := folderutil.GetFiles(tmpDir)
	if err != nil {
		return fmt.Errorf("could not open massdns output directory: %w", err)
	}

	for _, tmpFile := range tmpFiles {
		// just process stdout files
		if !stringsutil.ContainsAnyI(tmpFile, "stdout") {
			continue
		}
		err = instance.parseMassDNSOutputFile(tmpFile, store)
		if err != nil {
			return fmt.Errorf("could not parse massdns output: %w", err)
		}
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
	// Start to work in parallel on wildcards
	wildcardWg := sizedwaitgroup.New(instance.options.WildcardsThreads)

	var allCancelFunc []context.CancelFunc

	st.Iterate(func(ip string, hostnames []string, counter int) {
		ipCtx, ipCancelFunc := context.WithCancel(context.Background())
		allCancelFunc = append(allCancelFunc, ipCancelFunc)
		// We've stumbled upon a wildcard, just ignore it.
		if instance.wildcardStore.Has(ip) {
			return
		}

		// Perform wildcard detection on the ip, if an IP is found in the wildcard
		// we add it to the wildcard map so that further runs don't require such filtering again.
		if counter >= 5 || instance.options.StrictWildcard {
			for _, hostname := range hostnames {
				wildcardWg.Add()
				go func(ctx context.Context, ipCancelFunc context.CancelFunc, IP string, hostname string) {
					defer wildcardWg.Done()

					gologger.Info().Msgf("Started filtering wildcards for %s\n", hostname)

					select {
					case <-ctx.Done():
						return
					default:
					}

					isWildcard, ips := instance.wildcardResolver.LookupHost(hostname, IP)
					if len(ips) > 0 {
						for ip := range ips {
							// we add the single ip to the wildcard list
							if err := instance.wildcardStore.Set(ip); err != nil {
								gologger.Error().Msgf("could not set wildcard ip: %s", err)
							}
							gologger.Info().Msgf("Removing wildcard %s\n", ip)
						}
					}

					if isWildcard {
						// we also mark the original ip as wildcard, since at least once it resolved to this host
						if err := instance.wildcardStore.Set(IP); err != nil {
							gologger.Error().Msgf("could not set wildcard ip: %s", err)
						}
						ipCancelFunc()
						gologger.Info().Msgf("Removed wildcard %s\n", IP)
					}

				}(ipCtx, ipCancelFunc, ip, hostname)
			}
		}
	})

	wildcardWg.Wait()

	for _, cancelFunc := range allCancelFunc {
		cancelFunc()
	}

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
