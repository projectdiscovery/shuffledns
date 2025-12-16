package wildcards

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
)

const DefaultWildcardProbeCount = 3
const reProbeCount = 2

// Resolver represents a dns resolver for removing wildcards
type Resolver struct {
	Domains *sliceutil.SyncSlice[string]
	client  *dnsx.DNSX

	levelAnswersNormalCache *mapsutil.SyncLockMap[string, struct{}]
	wildcardAnswersCache    *mapsutil.SyncLockMap[string, wildcardAnswerCacheValue]

	probeCount int
}

type wildcardAnswerCacheValue struct {
	IPS *mapsutil.SyncLockMap[string, struct{}]
}

// NewResolver initializes and creates a new resolver to find wildcards
func NewResolver(domains []string, retries int, resolvers []string) (*Resolver, error) {
	fqdns := sliceutil.NewSyncSlice[string]()
	fqdns.Append(domains...)
	resolver := &Resolver{
		Domains:                 fqdns,
		levelAnswersNormalCache: mapsutil.NewSyncLockMap[string, struct{}](),
		wildcardAnswersCache:    mapsutil.NewSyncLockMap[string, wildcardAnswerCacheValue](),
		probeCount:              DefaultWildcardProbeCount,
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

// SetProbeCount sets the number of probes to use for wildcard detection.
// Higher values improve detection of wildcards using DNS round-robin.
func (w *Resolver) SetProbeCount(count int) {
	if count > 0 {
		w.probeCount = count
	}
}

// probeWildcardIPs probes the given wildcard pattern multiple times concurrently and returns all IPs found.
// Returns nil if the first probe returns NXDOMAIN (not a wildcard level).
// All queries are executed in parallel for better performance.
func (w *Resolver) probeWildcardIPs(pattern string, count int) []string {
	if count <= 0 {
		return nil
	}

	var wg sync.WaitGroup
	ips := sliceutil.NewSyncSlice[string]()

	// Launch all queries concurrently
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			probeHost := strings.ReplaceAll(pattern, "*.", xid.New().String()+".")
			in, err := w.client.QueryOne(probeHost)

			if err == nil && in != nil && in.StatusCodeRaw == dns.RcodeSuccess {
				ips.Append(in.A...)
			}
		}()
	}

	wg.Wait()

	// Check if first query failed (original behavior)
	if ips.Len() == 0 {
		return nil
	}

	return sliceutil.Dedupe(ips.Slice)
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
func (w *Resolver) LookupHost(host string, knownIPs []string) (bool, map[string]struct{}) {
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
		cachedValue, cachedValueOk := w.wildcardAnswersCache.Get(original)
		if cachedValueOk {
			for _, knownIP := range knownIPs {
				if _, ipExists := cachedValue.IPS.Get(knownIP); ipExists {
					return true, cachedValue.IPS.Map
				}
			}
			// Cache hit but IP not found - re-probe to catch missed round-robin IPs
			if extraIPs := w.probeWildcardIPs(original, reProbeCount); len(extraIPs) > 0 {
				for _, record := range extraIPs {
					wildcards[record] = struct{}{}
					_ = cachedValue.IPS.Set(record, struct{}{})
				}
				_ = w.wildcardAnswersCache.Set(original, cachedValue)
				for _, knownIP := range knownIPs {
					if _, ipExists := cachedValue.IPS.Get(knownIP); ipExists {
						return true, cachedValue.IPS.Map
					}
				}
			}
		}

		// Check if this level provides a normal response
		// ex. *.google.com which is not a wildcard and returns NXDOMAIN
		if _, ok := w.levelAnswersNormalCache.Get(original); ok {
			continue
		}

		// Multi-probe to capture all round-robin IPs
		probeIPs := w.probeWildcardIPs(original, w.probeCount)
		if probeIPs == nil {
			_ = w.levelAnswersNormalCache.Set(original, struct{}{})
			continue
		}

		if len(probeIPs) > 0 {
			if !cachedValueOk {
				cachedValue.IPS = mapsutil.NewSyncLockMap[string, struct{}]()
			}
			for _, record := range probeIPs {
				wildcards[record] = struct{}{}
				_ = cachedValue.IPS.Set(record, struct{}{})
			}
			_ = w.wildcardAnswersCache.Set(original, cachedValue)
			for _, knownIP := range knownIPs {
				if _, ipExists := cachedValue.IPS.Get(knownIP); ipExists {
					return true, cachedValue.IPS.Map
				}
			}

			// Resolve actual host multiple times to catch round-robin IPs
			// This is final case tr
			for i := 0; i < w.probeCount; i++ {
				in, err := w.client.QueryOne(host)
				if err == nil && in != nil && in.StatusCodeRaw == dns.RcodeSuccess {
					for _, record := range in.A {
						if _, ipExists := cachedValue.IPS.Get(record); ipExists {
							return true, cachedValue.IPS.Map
						}
					}
				}
			}
		}
	}

	// check if any of the knownIPs are among wildcards
	for _, knownIP := range knownIPs {
		if _, ok := wildcards[knownIP]; ok {
			return true, wildcards
		}
	}

	return false, wildcards
}

func (w *Resolver) GetAllWildcardIPs() map[string]struct{} {
	ips := make(map[string]struct{})

	_ = w.wildcardAnswersCache.Iterate(func(key string, value wildcardAnswerCacheValue) error {
		for ip := range value.IPS.Map {
			if _, ok := ips[ip]; !ok {
				ips[ip] = struct{}{}
			}
		}
		return nil
	})
	return ips
}
