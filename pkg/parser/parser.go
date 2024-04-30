package parser

import (
	"bufio"
	"io"
	"os"
	"strings"
)

type OnResultFN func(domain string, ip []string) error

func ParseFile(filename string, onResult OnResultFN) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return ParseReader(file, onResult)
}

// Parse parses the massdns output returning the found
// domain and ip pair to a onResult function.
func ParseReader(reader io.Reader, onResult OnResultFN) error {
	var (
		// Some boolean various needed for state management
		cnameStart bool
		nsStart    bool

		// Result variables to store the results
		domain string
		ip     []string
	)

	// Parse the input line by line and act on what the line means
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		text := scanner.Text()

		// Empty line represents a seperator between DNS reply
		// due to `-o Snl` option set in massdns. Thus it can be
		// interpreted as a DNS answer header.
		//
		// If we have start of a DNS answer header, set the
		// bool state to default, and return the results to the
		// consumer via the callback.
		if text == "" {
			if domain != "" {
				cnameStart, nsStart = false, false
				if err := onResult(domain, ip); err != nil {
					return err
				}
				domain, ip = "", nil
			}
		} else {
			// Non empty line represents DNS answer section, we split on space,
			// iterate over all the parts, and write the answer to the struct.
			parts := strings.Split(text, " ")

			if len(parts) != 3 {
				continue
			}

			// Switch on the record type, deciding what to do with
			// a record based on the type of record.
			switch parts[1] {
			case "NS":
				// If we have a NS record, then set nsStart
				// which will ignore all the next records
				nsStart = true
			case "CNAME":
				// If we have a CNAME record, then the next record should be
				// the values for the CNAME record, so set the cnameStart value.
				//
				// Use the domain in the first cname field since the next fields for
				// A record may contain domain for secondary CNAME which messes
				// up recursive CNAME records.
				if !cnameStart {
					nsStart = false
					domain = strings.TrimSuffix(parts[0], ".")
					cnameStart = true
				}
			case "A":
				// If we have an A record, check if it's not after
				// an NS record. If not, append it to the ips.
				//
				// Also if we aren't inside a CNAME block, set the domain too.
				if !nsStart {
					if !cnameStart && domain == "" {
						domain = strings.TrimSuffix(parts[0], ".")
					}
					ip = append(ip, parts[2])
				}
			}
		}
	}

	// Return error if there was any.
	if err := scanner.Err(); err != nil {
		return err
	}

	// Final callback to deliver the last piece of result
	// if there's any.
	if domain != "" {
		if err := onResult(domain, ip); err != nil {
			return err
		}
	}
	return nil
}
