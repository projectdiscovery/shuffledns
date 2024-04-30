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
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/projectdiscovery/shuffledns/pkg/store"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/remeh/sizedwaitgroup"
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
	args := []string{"-r", instance.options.ResolversFile, "-o", "Snl", "-t", "A", instance.options.InputFile, "-s", strconv.Itoa(instance.options.Threads)}
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
	blank, err := IsBlankFile(inputFile)
	if err != nil {
		return err
	}
	if blank {
		return errors.New("blank input file specified")
	}

	// Create a store for storing ip metadata
	shstore := store.New()
	defer shstore.Close()

	// Set the correct target file
	tmpDir := instance.options.TempDir

	// Check if we need to run massdns
	if instance.options.MassdnsRaw == "" {
		if instance.options.Domain != "" {
			gologger.Info().Msgf("Executing massdns on %s\n", instance.options.Domain)
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
	}

	gologger.Info().Msgf("Started parsing massdns output\n")

	err = instance.parseMassDNSOutputDir(tmpDir, shstore)
	if err != nil {
		return fmt.Errorf("could not parse massdns output: %w", err)
	}

	gologger.Info().Msgf("Massdns output parsing completed\n")

	// Perform wildcard filtering only if domain name has been specified
	if instance.options.Domain != "" {
		gologger.Info().Msgf("Started removing wildcards records\n")
		err = instance.filterWildcards(shstore)
		if err != nil {
			return fmt.Errorf("could not parse massdns output: %w", err)
		}
		gologger.Info().Msgf("Wildcard removal completed\n")
	}

	gologger.Info().Msgf("Finished enumeration, started writing output\n")

	// Write the final elaborated list out
	return instance.writeOutput(shstore)
}

func (instance *Instance) parseMassDNSOutputFile(tmpFile string, store *store.Store) error {
	massdnsOutput, err := os.Open(tmpFile)
	if err != nil {
		return fmt.Errorf("could not open massdns output file: %w", err)
	}
	defer massdnsOutput.Close()

	// at first we need the full structure in memory to elaborate it in parallell
	err = parser.Parse(massdnsOutput, func(domain string, ip []string) {
		for _, ip := range ip {
			// Check if ip exists in the store. If not,
			// add the ip to the map and continue with the next ip.
			if !store.Exists(ip) {
				store.New(ip, domain)
				continue
			}

			// Get the IP meta-information from the store.
			record := store.Get(ip)

			// Put the new hostname and increment the counter by 1.
			record.Hostnames[domain] = struct{}{}
			record.Counter++
		}
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
		err = instance.parseMassDNSOutputFile(tmpFile, store)
		if err != nil {
			return fmt.Errorf("could not parse massdns output: %w", err)
		}
	}

	return nil
}

func (instance *Instance) filterWildcards(st *store.Store) error {
	// Start to work in parallel on wildcards
	wildcardWg := sizedwaitgroup.New(instance.options.WildcardsThreads)

	for _, record := range st.IP {
		// We've stumbled upon a wildcard, just ignore it.
		if instance.wildcardIPMap.Has(record.IP) {
			continue
		}

		// Perform wildcard detection on the ip, if an IP is found in the wildcard
		// we add it to the wildcard map so that further runs don't require such filtering again.
		if record.Counter >= 5 || instance.options.StrictWildcard {
			wildcardWg.Add()
			go func(record *store.IPMeta) {
				defer wildcardWg.Done()

				for host := range record.Hostnames {
					isWildcard, ips := instance.wildcardResolver.LookupHost(host)
					if len(ips) > 0 {
						for ip := range ips {
							// we add the single ip to the wildcard list
							if err := instance.wildcardIPMap.Set(ip, struct{}{}); err != nil {
								gologger.Error().Msgf("could not set wildcard ip: %s", err)
							}
						}
					}

					if isWildcard {
						// we also mark the original ip as wildcard, since at least once it resolved to this host
						if err := instance.wildcardIPMap.Set(record.IP, struct{}{}); err != nil {
							gologger.Error().Msgf("could not set wildcard ip: %s", err)
						}
						break
					}
				}
			}(record)
		}
	}

	wildcardWg.Wait()

	// drop all wildcard from the store
	return instance.wildcardIPMap.Iterate(func(k string, v struct{}) error {
		st.Delete(k)
		return nil
	})
}

func (instance *Instance) writeOutput(store *store.Store) error {
	// Write the unique deduplicated output to the file or stdout
	// depending on what the user has asked.
	var output *os.File
	var w *bufio.Writer
	var err error

	if instance.options.OutputFile != "" {
		output, err = os.Create(instance.options.OutputFile)
		if err != nil {
			return fmt.Errorf("could not create massdns output file: %v", err)
		}
		w = bufio.NewWriter(output)
	}
	buffer := &strings.Builder{}

	uniqueMap := make(map[string]struct{})

	// write count of resolved hosts
	resolvedCount := 0
	for _, record := range store.IP {
		if instance.options.OnResult != nil {
			instance.options.OnResult(record)
		}

		for hostname := range record.Hostnames {
			// Skip if we already printed this subdomain once
			if _, ok := uniqueMap[hostname]; ok {
				continue
			}
			uniqueMap[hostname] = struct{}{}

			if instance.options.Json {
				hostnameJson, err := json.Marshal(map[string]interface{}{"hostname": hostname})
				if err != nil {
					return fmt.Errorf("could not marshal output as json: %v", err)
				}

				buffer.WriteString(string(hostnameJson))
				buffer.WriteString("\n")
			} else {
				buffer.WriteString(hostname)
				buffer.WriteString("\n")
			}

			data := buffer.String()

			if output != nil {
				_, _ = w.WriteString(data)
			}
			gologger.Silent().Msgf("%s", data)
			buffer.Reset()
			resolvedCount++
		}
	}
	gologger.Info().Msgf("Total resolved: %d\n", resolvedCount)

	// Close the files and return
	if output != nil {
		w.Flush()
		output.Close()
	}
	return nil
}
