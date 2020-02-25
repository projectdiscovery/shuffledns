package parser

import (
	"bufio"
	"io"
	"strings"
)

// Callback is a callback function that is called by
// the parser returning the results found.
// NOTE: Callbacks are not thread safe and are blocking in nature
// and should be used as such.
type Callback func(domain string, ip []string)

// Parse parses the massdns output returning the found
// domain and ip pair to a callback function.
//
// It's a pretty hacky solution. In future, it can and should
// be rewritten to handle more edge cases and stuff.
func Parse(reader io.Reader, callback Callback) error {
	var (
		// Some boolean various needed for state management
		answerStart bool
		cnameStart  bool
		nsStart     bool

		// Result variables to store the results
		domain string
		ip     []string
	)

	// Parse the input line by line and act on what the line means
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		// Ignore fields with less than 4 characters
		if len(text) < 4 {
			continue
		}

		// If we have start of a DNS answer header, set the
		// bool state to default, and return the results to the
		// consumer via the callback.
		if text[0] == ';' && text[1] == ';' && text[2] == ' ' && text[3] == 'A' && text[4] == 'N' {
			if domain != "" {
				cnameStart, nsStart = false, false
				callback(domain, ip)
				domain, ip = "", nil
			}
			answerStart = true
			continue
		}

		// If we are expecting a DNS answer, we split on space,
		// iterate over all the parts, and write the answer to the struct.
		if answerStart {
			parts := strings.Split(text, " ")

			if len(parts) != 5 {
				continue
			}

			// Switch on the record type, deciding what to do with
			// a record based on the type of record.
			switch parts[3] {
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
					ip = append(ip, parts[4])
				}
			}
		}
		continue
	}

	// Return error if there was any.
	if err := scanner.Err(); err != nil {
		return err
	}

	// Final callback to deliver the last piece of result
	// if there's any.
	if domain != "" {
		callback(domain, ip)
	}
	return nil
}
