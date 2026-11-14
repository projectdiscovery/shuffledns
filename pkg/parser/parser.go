package parser

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// OnResultFN is the callback invoked for each parsed DNS reply.
// resolver is the IP address (without port) of the resolver that
// answered the query when massdns was run with the `r` simple
// output flag (-o Snlr). When the metadata line is missing
// resolver will be an empty string.
type OnResultFN func(domain string, ip []string, resolver string) error

func ParseFile(filename string, onResult OnResultFN) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	return ParseReader(file, onResult)
}

// Parse parses the massdns output returning the found
// domain and ip pair to a onResult function.
//
// The parser supports both the legacy `-o Snl` output and the
// `-o Snlr` output, where each reply block is prefixed by a
// metadata line in the form:
//
//	<resolver_ip:port> <unix_ts> <rcode> <name> [class] <type>
//
// When present, the resolver IP is extracted and forwarded to
// the OnResultFN callback so consumers can correlate answers
// back to the resolver that produced them.
func ParseReader(reader io.Reader, onResult OnResultFN) error {
	var (
		// Some boolean various needed for state management
		cnameStart bool
		nsStart    bool

		// Result variables to store the results
		domain   string
		ip       []string
		resolver string
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
				if err := onResult(domain, ip, resolver); err != nil {
					return err
				}
				domain, ip, resolver = "", nil, ""
			}
		} else {
			// Non empty line represents DNS answer section, we split on space,
			// iterate over all the parts, and write the answer to the struct.
			parts := strings.Fields(text)

			// A metadata line (massdns `r` flag) has the shape
			// "<resolver_ip:port> <ts> <rcode> <name> [class] <type>".
			// Detect it by checking that the second field is a
			// numeric Unix timestamp; if so, capture the resolver
			// and skip to the next line.
			if maybeResolver, ok := parseResolverFromMetaLine(parts); ok {
				resolver = maybeResolver
				continue
			}

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
		if err := onResult(domain, ip, resolver); err != nil {
			return err
		}
	}
	return nil
}

// parseResolverFromMetaLine inspects the fields of a line and, if
// it matches the metadata layout produced by massdns when the `r`
// simple output flag is set, returns the resolver IP (without
// port and without IPv6 brackets).
func parseResolverFromMetaLine(parts []string) (string, bool) {
	// Without TTL the line has 5 fields (class is empty),
	// with TTL it has 6.
	if len(parts) < 5 || len(parts) > 6 {
		return "", false
	}

	if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
		return "", false
	}

	addr := parts[0]
	var ip string
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end <= 1 {
			return "", false
		}
		ip = addr[1:end]
	} else {
		idx := strings.LastIndex(addr, ":")
		if idx <= 0 {
			return "", false
		}
		ip = addr[:idx]
	}

	if ip == "" {
		return "", false
	}
	return ip, true
}
