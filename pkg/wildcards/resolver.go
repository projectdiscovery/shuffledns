package wildcards

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/roundrobin/transport"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
)

// Resolver represents a dns resolver for removing wildcards
type Resolver struct {
	servers    *transport.RoundTransport
	domains    []string
	maxRetries int
}

// NewResolver initializes and creates a new resolver to find wildcards
func NewResolver(domains []string, retries int) (*Resolver, error) {
	resolver := &Resolver{
		domains:    domains,
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
	servers, err := LoadResolversFromFile(file)
	if err != nil {
		return err
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

	var domain string
	for _, domainCandidate := range w.domains {
		if stringsutil.HasSuffixAny(host, "."+domainCandidate) {
			domain = domainCandidate
			break
		}
	}

	// ignore records without domain (todo: might be interesting to detect dangling domains)
	if domain == "" {
		gologger.Info().Msgf("no domain found - skipping: %s", host)
		return false, nil
	}

	subdomainPart := strings.TrimSuffix(host, "."+domain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, host)
	hosts = append(hosts, xid.New().String()+"."+domain)

	for i := 0; i < len(subdomainTokens); i++ {
		newhost := xid.New().String() + "." + strings.Join(subdomainTokens[i:], ".") + "." + domain
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
