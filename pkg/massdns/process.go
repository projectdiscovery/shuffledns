package massdns

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/internal/store"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/rs/xid"
)

// Process runs the actual enumeration process returning a file
func (c *Client) Process() error {
	// Check for blank input file or non-existent input file
	blank, err := IsBlankFile(c.config.InputFile)
	if err != nil {
		return err
	}
	if blank {
		return errors.New("blank input file specified")
	}

	// Create a store for storing ip metadata
	store := store.New()
	defer store.Close()

	// Create a temporary file for the massdns output
	temporaryOutput := path.Join(c.config.TempDir, xid.New().String())

	gologger.Infof("Creating temporary massdns output file: %s\n", temporaryOutput)
	gologger.Infof("Executing massdns on %s\n", c.config.Domain)

	now := time.Now()
	// Run the command on a temp file and wait for the output
	cmd := exec.Command(c.config.MassdnsPath, []string{"-r", c.config.ResolversFile, "-t", "A", c.config.InputFile, "-w", temporaryOutput, "-s", strconv.Itoa(c.config.Threads)}...)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("could not execute massdns: %w", err)
	}
	gologger.Infof("Massdns execution took %s\n", time.Now().Sub(now))

	massdnsOutput, err := os.Open(temporaryOutput)
	if err != nil {
		return fmt.Errorf("could not open massdns output file: %w", err)
	}
	defer massdnsOutput.Close()

	gologger.Infof("Parsing output and removing wildcards\n")

	err = parser.Parse(massdnsOutput, func(domain string, ip []string) {
		for _, ip := range ip {
			// We've stumbled upon a wildcard, just ignore it.
			if _, ok := c.wildcardIPMap[ip]; ok {
				break
			}

			// Check if ip exists in the store. If not,
			// add the ip to the map and continue with the next ip.
			if !store.Exists(ip) {
				store.New(ip, domain)
				continue
			}

			// Get the IP meta-information from the store.
			record := store.Get(ip)

			// If the same ip has been found more than 5 times, perform wildcard detection
			// on it now, if an IP is found in the wildcard, we delete all hostnames associated
			// with it, also we add it to the wildcard map so that further runs don't require such
			// filtering again.
			if record.Counter >= 5 && !record.Validated {
				for _, host := range record.Hostnames {
					wildcard, ips := c.wildcardResolver.LookupHost(host)
					if wildcard {
						for ip := range ips {
							store.Delete(ip)
							c.wildcardIPMap[ip] = struct{}{}
						}

						// Exit out of the loop if we've found a wildcard and test no more
						// hosts having the same IP.
						break
					}
					// If not a wildcard, then add the IPs to the exclusion
					// map and don't perform any further checking for wildcards on them.
					record.Validated = true
				}
			}
			// Put the new hostname and increment the counter by 1.
			record.Hostnames = append(record.Hostnames, domain)
			record.Counter++
		}
	})
	if err != nil {
		return fmt.Errorf("could not parse massdns output: %w", err)
	}
	gologger.Infof("Finished enumeration, started writing output\n")

	// Parse the massdns output
	return c.writeOutput(store)
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
	for _, record := range store.IP {
		for _, hostname := range record.Hostnames {
			buffer.WriteString(hostname)
			buffer.WriteString("\n")
			data := buffer.String()

			// Check if we don't have a duplicate
			if _, ok := uniqueMap[data]; !ok {
				uniqueMap[data] = struct{}{}

				if output != nil {
					w.WriteString(data)
				}
				gologger.Silentf("%s", data)
				buffer.Reset()
			}
		}
	}

	// Close the files and return
	if output != nil {
		w.Flush()
		output.Close()
	}
	return nil
}
