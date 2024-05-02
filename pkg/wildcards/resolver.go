package wildcards

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
)

// Resolver represents a dns resolver for removing wildcards
type Resolver struct {
	domains []string
	client  *dnsx.DNSX
}

// NewResolver initializes and creates a new resolver to find wildcards
func NewResolver(domains []string, retries int, resolvers []string) (*Resolver, error) {
	resolver := &Resolver{
		domains: domains,
	}

	options := dnsx.DefaultOptions
	options.BaseResolvers = resolvers
	options.MaxRetries = retries
	dnsResolver, err := dnsx.New(options)
	if err != nil {
		return nil, fmt.Errorf("could not create dns resolver: %w", err)
	}
	resolver.client = dnsResolver

	return resolver, nil
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
		// Create a dns message and send it to the server
		in, err := w.client.QueryOne(host)
		if err != nil {
			continue
		}
		// Skip the current host since we can't resolve it
		if in != nil && in.StatusCodeRaw != dns.RcodeSuccess {
			continue
		}

		// Get all the records and add them to the wildcard map
		for _, record := range in.A {
			if host == h {
				orig[record] = struct{}{}
				continue
			}

			if _, ok := wildcards[record]; !ok {
				wildcards[record] = struct{}{}
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
