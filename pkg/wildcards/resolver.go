package wildcards

import (
	"bufio"
	"os"
	"strings"

	"github.com/Mzack9999/roundrobin/transport"
	"github.com/miekg/dns"
	"github.com/rs/xid"
)

// Resolver represents a dns resolver for removing wildcards
type Resolver struct {
	// servers contains the dns servers to use
	servers *transport.RoundTransport
	// domain is the domain to perform enumeration on
	domain string
	// maxRetries is the maximum number of retries allowed
	maxRetries int
}

// NewResolver initializes and creates a new resolver to find wildcards
func NewResolver(domain string, retries int) (*Resolver, error) {
	resolver := &Resolver{
		domain:     domain,
		maxRetries: retries,
	}
	return resolver, nil
}

// AddServersFromList adds the resolvers from a list of servers
func (w *Resolver) AddServersFromList(list []string) {
	for i := 0; i < len(list); i++ {
		list[i] = list[i] + ":53"
	}
	w.servers, _ = transport.New(list...)
}

// AddServersFromFile adds the resolvers from a file to the list of servers
func (w *Resolver) AddServersFromFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		servers = append(servers, text+":53")
	}

	w.servers, _ = transport.New(servers...)

	return nil
}

// LookupHost returns wildcard IP addresses of a wildcard if it's a wildcard.
// To determine, first we split the target host by dots, create permutation
// of it's levels, check for wildcard on each one of them and if found any,
// we remove all the hosts that have this IP from the map.
func (w *Resolver) LookupHost(host string) (bool, map[string]struct{}) {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	subdomainPart := strings.TrimSuffix(host, "."+w.domain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, host)
	hosts = append(hosts, xid.New().String()+"."+w.domain)

	for i := 0; i < len(subdomainTokens); i++ {
		newhost := xid.New().String() + "." + strings.Join(subdomainTokens[i:], ".") + "." + w.domain
		hosts = append(hosts, newhost)
	}

	// Iterate over all the hosts generated for rand.
	for _, h := range hosts {
		resolver := w.servers.Next()
		var retryCount int
	retry:
		// Create a dns message and send it to the server
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.RecursionDesired = true
		m.Question = make([]dns.Question, 1)
		question := dns.Fqdn(h)
		m.Question[0] = dns.Question{
			Name:   question,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}
		in, err := dns.Exchange(m, resolver)
		if err != nil {
			if retryCount < w.maxRetries {
				retryCount++
				goto retry
			}
			// Skip the current host if there are no more retries
			retryCount = 0
			continue
		}

		// Skip the current host since we can't resolve it
		if in != nil && in.Rcode != dns.RcodeSuccess {
			continue
		}

		// Get all the records and add them to the wildcard map
		for _, record := range in.Answer {
			if t, ok := record.(*dns.A); ok {
				r := t.A.String()

				if host == h {
					orig[r] = struct{}{}
					continue
				}

				if _, ok := wildcards[r]; !ok {
					wildcards[r] = struct{}{}
				}
			}
		}
	}

	// check if original ip are among wildcards
	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true, wildcards
		}
	}

	return false, wildcards
}
