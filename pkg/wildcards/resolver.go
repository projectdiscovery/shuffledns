package wildcards

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
)

// Resolver represents a dns resolver for removing wildcards
type Resolver struct {
	Domains *sliceutil.SyncSlice[string]
	client  *dnsx.DNSX

	levelAnswersNormalCache *mapsutil.SyncLockMap[string, struct{}]
	wildcardAnswersCache    *mapsutil.SyncLockMap[string, struct{}]
}

// NewResolver initializes and creates a new resolver to find wildcards
func NewResolver(domains []string, retries int, resolvers []string) (*Resolver, error) {
	fqdns := sliceutil.NewSyncSlice[string]()
	fqdns.Append(domains...)
	resolver := &Resolver{
		Domains:                 fqdns,
		levelAnswersNormalCache: mapsutil.NewSyncLockMap[string, struct{}](),
		wildcardAnswersCache:    mapsutil.NewSyncLockMap[string, struct{}](),
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

// generateWildcardPermutations generates wildcard permutations for a given subdomain
// and domain. It generates permutations for each level of the subdomain
// in reverse order.
func generateWildcardPermutations(subdomain, domain string) []string {
	var hosts []string
	subdomainTokens := strings.Split(subdomain, ".")

	var builder strings.Builder
	builder.Grow(len(subdomain) + len(domain) + 5)

	// Iterate from the reverse order. This way we generate the roots
	// first and allows us to do filtering faster, by trying out the root
	// like *.example.com first, and *.child.example.com in that order.
	// If we get matches for the root, we can skip the child and rest
	builder.WriteString("*.")
	builder.WriteString(domain)
	hosts = append(hosts, builder.String())
	builder.Reset()

	for i := len(subdomainTokens); i > 1; i-- {
		_, _ = builder.WriteString("*.")
		_, _ = builder.WriteString(strings.Join(subdomainTokens[i-1:], "."))
		_, _ = builder.WriteRune('.')
		_, _ = builder.WriteString(domain)
		hosts = append(hosts, builder.String())
		builder.Reset()
	}
	return hosts
}

// LookupHost returns wildcard IP addresses of a wildcard if it's a wildcard.
// To determine, first we split the target host by dots, create permutation
// of it's levels, check for wildcard on each one of them and if found any,
// we remove all the hosts that have this IP from the map.
func (w *Resolver) LookupHost(host string) (bool, map[string]struct{}) {
	orig := make(map[string]struct{})
	ips, err := w.client.QueryOne(host)
	if err != nil {
		return false, nil
	}
	for _, ip := range ips.A {
		orig[ip] = struct{}{}
	}

	wildcards := make(map[string]struct{})

	var domain string
	w.Domains.Each(func(i int, domainCandidate string) error {
		if stringsutil.HasSuffixAny(host, "."+domainCandidate) {
			domain = domainCandidate
			// just to interrupt the iteration
			return errors.New("found domain")
		}
		return nil
	})

	// ignore records without domain (todo: might be interesting to detect dangling domains)
	if domain == "" {
		gologger.Info().Msgf("no domain found - skipping: %s", host)
		return false, nil
	}

	subdomainPart := strings.TrimSuffix(host, "."+domain)

	// create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	hosts := generateWildcardPermutations(subdomainPart, domain)

	// Iterate over all the hosts generated for rand.
	for _, h := range hosts {
		h = strings.TrimSuffix(h, ".")

		original := h

		// Check if we have already resolved this host level successfully
		// and if so, use the cached answer
		//
		// ex. *.campaigns.google.com is a wildcard so we cache it
		// and it is used always for resolutions in future.
		if _, ok := w.wildcardAnswersCache.Get(original); ok {
			for record := range orig {
				wildcards[record] = struct{}{}
			}
			return true, wildcards
		}

		// Check if this level provides a normal response
		// ex. *.google.com which is not a wildcard and returns NXDOMAIN
		if _, ok := w.levelAnswersNormalCache.Get(original); ok {
			continue
		}

		h = strings.ReplaceAll(h, "*.", xid.New().String()+".")

		// Create a dns message and send it to the server
		in, err := w.client.QueryOne(h)
		if err != nil {
			continue
		}
		// Store this as well to be used for caching other levels
		// so lookups don't happen as frequently.

		// Skip the current host since we can't resolve it
		if in != nil && in.StatusCodeRaw != dns.RcodeSuccess {
			_ = w.levelAnswersNormalCache.Set(original, struct{}{})
			continue
		}

		// Get all the records and add them to the wildcard map
		for _, record := range in.A {
			if _, ok := wildcards[record]; !ok {
				wildcards[record] = struct{}{}
			}
		}
		_ = w.wildcardAnswersCache.Set(original, struct{}{})
		break
	}

	// check if original ip are among wildcards
	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true, wildcards
		}
	}

	return false, wildcards
}
