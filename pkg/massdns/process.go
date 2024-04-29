package massdns

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/projectdiscovery/shuffledns/pkg/store"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/xid"
)

// Process runs the actual enumeration process returning a file
func (c *Client) Process() error {
	// Process a created list or the massdns input
	inputFile := c.config.InputFile
	if c.config.MassdnsRaw != "" {
		inputFile = c.config.MassdnsRaw
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
	tmpDir := c.config.TempDir
	massDNSOutput := filepath.Join(tmpDir, xid.New().String())
	if c.config.MassdnsRaw != "" {
		massDNSOutput = c.config.MassdnsRaw
	}

	// Check if we need to run massdns
	if c.config.MassdnsRaw == "" {
		// Create a temporary file for the massdns output
		gologger.Info().Msgf("Creating temporary massdns output directory: %s\n", tmpDir)
		err = c.runMassDNS(massDNSOutput)
		if err != nil {
			return fmt.Errorf("could not execute massdns: %w", err)
		}
	}

	gologger.Info().Msgf("Started parsing massdns output\n")

	err = c.parseMassDNSOutputDir(tmpDir, shstore)
	if err != nil {
		return fmt.Errorf("could not parse massdns output: %w", err)
	}

	gologger.Info().Msgf("Massdns output parsing completed\n")

	// Perform wildcard filtering only if domain name has been specified
	if c.config.Domain != "" {
		gologger.Info().Msgf("Started removing wildcards records\n")
		err = c.filterWildcards(shstore)
		if err != nil {
			return fmt.Errorf("could not parse massdns output: %w", err)
		}
		gologger.Info().Msgf("Wildcard removal completed\n")
	}

	gologger.Info().Msgf("Finished enumeration, started writing output\n")

	// Write the final elaborated list out
	return c.writeOutput(shstore)
}

func (c *Client) runMassDNS(output string) error {
	if c.config.Domain != "" {
		gologger.Info().Msgf("Executing massdns on %s\n", c.config.Domain)
	} else {
		gologger.Info().Msgf("Executing massdns\n")
	}
	now := time.Now()
	// Run the command on a temp file and wait for the output
	args := []string{"-r", c.config.ResolversFile, "-o", "Snl", "-t", "A", c.config.InputFile, "-w", output, "-s", strconv.Itoa(c.config.Threads)}
	if c.config.MassDnsCmd != "" {
		args = append(args, strings.Split(c.config.MassDnsCmd, " ")...)
	}
	cmd := exec.Command(c.config.MassdnsPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("could not execute massdns: %w\ndetailed error: %s", err, stderr.String())
	}
	gologger.Info().Msgf("Massdns execution took %s\n", time.Since(now))
	return nil
}

func (c *Client) parseMassDNSOutputFile(tmpFile string, store *store.Store) error {
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

func (c *Client) parseMassDNSOutputDir(tmpDir string, store *store.Store) error {
	tmpFiles, err := folderutil.GetFiles(tmpDir)
	if err != nil {
		return fmt.Errorf("could not open massdns output directory: %w", err)
	}

	for _, tmpFile := range tmpFiles {
		err = c.parseMassDNSOutputFile(tmpFile, store)
		if err != nil {
			return fmt.Errorf("could not parse massdns output: %w", err)
		}
	}

	return nil
}

func (c *Client) filterWildcards(st *store.Store) error {
	// Start to work in parallel on wildcards
	wildcardWg := sizedwaitgroup.New(c.config.WildcardsThreads)

	for _, record := range st.IP {
		// We've stumbled upon a wildcard, just ignore it.
		if c.wildcardIPMap.Has(record.IP) {
			continue
		}

		// Perform wildcard detection on the ip, if an IP is found in the wildcard
		// we add it to the wildcard map so that further runs don't require such filtering again.
		if record.Counter >= 5 || c.config.StrictWildcard {
			wildcardWg.Add()
			go func(record *store.IPMeta) {
				defer wildcardWg.Done()

				for host := range record.Hostnames {
					isWildcard, ips := c.wildcardResolver.LookupHost(host)
					if len(ips) > 0 {
						for ip := range ips {
							// we add the single ip to the wildcard list
							c.wildcardIPMap.Set(ip, struct{}{})
						}
					}

					if isWildcard {
						// we also mark the original ip as wildcard, since at least once it resolved to this host
						if err := c.wildcardIPMap.Set(record.IP, struct{}{}); err != nil {
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
	return c.wildcardIPMap.Iterate(func(k string, v struct{}) error {
		st.Delete(k)
		return nil
	})
}

func (c *Client) writeOutput(store *store.Store) error {
	// Write the unique deduplicated output to the file or stdout
	// depending on what the user has asked.
	var output *os.File
	var w *bufio.Writer
	var err error

	if c.config.OutputFile != "" {
		output, err = os.Create(c.config.OutputFile)
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
		if c.config.OnResult != nil {
			c.config.OnResult(record)
		}

		for hostname := range record.Hostnames {
			// Skip if we already printed this subdomain once
			if _, ok := uniqueMap[hostname]; ok {
				continue
			}
			uniqueMap[hostname] = struct{}{}

			if c.config.Json {
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
