package massdns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/projectdiscovery/shuffledns/pkg/store"
	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/remeh/sizedwaitgroup"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// runs massdns binary with the specified options
func (instance *Instance) RunWithContext(ctx context.Context) (stdout, stderr string, took time.Duration, err error) {
	start := time.Now()

	stdoutFile, err := os.CreateTemp(instance.options.TempDir, "massdns-stdout-")
	if err != nil {
		return "", "", 0, fmt.Errorf("could not create temp file for massdns stdout: %w", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(instance.options.TempDir, "massdns-stderr-")
	if err != nil {
		return "", "", 0, fmt.Errorf("could not create temp file for massdns stdout: %w", err)
	}
	defer stderrFile.Close()

	// Run the command on a temp file and wait for the output
	args := []string{"-r", instance.options.ResolversFile, "-o", "Snl", "--retry", "REFUSED", "--retry", "SERVFAIL", "-t", "A", instance.options.InputFile, "-s", strconv.Itoa(instance.options.Threads)}
	if instance.options.MassDnsCmd != "" {
		args = append(args, strings.Split(instance.options.MassDnsCmd, " ")...)
	}
	cmd := exec.CommandContext(ctx, instance.options.MassdnsPath, args...)
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	err = cmd.Run()
	return stdoutFile.Name(), stderrFile.Name(), time.Since(start), err
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

	// Set the correct target file
	tmpDir := instance.options.TempDir

	// Check if we need to run massdns
	if instance.options.MassdnsRaw == "" {
		if len(instance.options.Domains) > 0 {
			gologger.Info().Msgf("Executing massdns on %s\n", strings.Join(instance.options.Domains, ", "))
		} else {
			gologger.Info().Msgf("Executing massdns\n")
		}

		// Create a temporary file for the massdns output
		gologger.Info().Msgf("using massdns output directory: %s\n", tmpDir)
		stdoutFile, stderrFile, took, err := instance.RunWithContext(ctx)
		gologger.Info().Msgf("massdns output file: %s\n", stdoutFile)
		gologger.Info().Msgf("massdns error file: %s\n", stderrFile)
		if err != nil {
			return fmt.Errorf("could not execute massdns: %s", err)
		}

		gologger.Info().Msgf("Massdns execution took %s\n", took)

		gologger.Info().Msgf("Started parsing massdns output\n")

		now := time.Now()

		err = instance.parseMassDNSOutputDir(tmpDir, shstore)
		if err != nil {
			return fmt.Errorf("could not parse massdns output: %w", err)
		}

		gologger.Info().Msgf("Massdns output parsing completed in %s\n", time.Since(now))
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

func (instance *Instance) parseMassDNSOutputFile(tmpFile string, store *store.Store) error {
	// at first we need the full structure in memory to elaborate it in parallell
	err := parser.ParseFile(tmpFile, func(domain string, ip []string) error {
		for _, ip := range ip {
			// Check if ip exists in the store. If not,
			// add the ip to the map and continue with the next ip.
			if !store.Exists(ip) {
				if err := store.New(ip, domain); err != nil {
					return fmt.Errorf("could not create new record: %w", err)
				}
				continue
			}

			if err := store.Update(ip, domain); err != nil {
				return fmt.Errorf("could not update record: %w", err)
			}
		}
		return nil
	})

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
							gologger.Debug().Msgf("Removing wildcard %s\n", ip)
						}
					}

					if isWildcard {
						// we also mark the original ip as wildcard, since at least once it resolved to this host
						if err := instance.wildcardStore.Set(IP); err != nil {
							gologger.Error().Msgf("could not set wildcard ip: %s", err)
						}
						ipCancelFunc()
						gologger.Debug().Msgf("Removed wildcard %s\n", IP)
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
	var output *os.File
	var w *bufio.Writer
	var err error
	var wMut = &sync.Mutex{}

	if instance.options.OutputFile != "" {
		output, err = os.Create(instance.options.OutputFile)
		if err != nil {
			return fmt.Errorf("could not create massdns output file: %v", err)
		}
		w = bufio.NewWriter(output)
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
					wMut.Lock()
					_, _ = w.WriteString(data)
					wMut.Unlock()
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
		w.Flush()
		output.Close()
	}
	return nil
}
