package massdns

import (
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
)

type Instance struct {
	options Options

	wildcardStore *wildcards.Store

	wildcardResolver *wildcards.Resolver
}

type Options struct {
	// AutoExtractRootDomains is used to extract root domains from the input list of subdomains
	AutoExtractRootDomains bool
	// Domain is the domain specified for enumeration
	Domains []string
	// Retries is the number of retries for dns
	Retries int
	// Threads is the number of concurrent in-flight dns queries
	Threads int
	// ResolversFile is the file with the resolvers
	ResolversFile string
	// TrustedResolvers is the file with the trusted resolvers
	TrustedResolvers string
	// TempDir is a temporary directory for storing misc files
	TempDir string
	// OutputFile is the file to write results to
	OutputFile string
	// Json is format ouput to ndjson format
	Json bool
	// WildcardsThreads is the number of wildcards concurrent threads
	WildcardsThreads int
	// MassdnsRaw performs wildcards filtering from an existing massdns output file
	MassdnsRaw string
	// StrictWildcard controls whether the wildcard check should be performed on each result
	StrictWildcard bool
	// WildcardOutputFile is the file where the list of wildcards is dumped
	WildcardOutputFile string
	// FilterInternalIPs controls whether to filter out internal/private IP addresses
	FilterInternalIPs bool

	// Native resolver tuning (forwarded to pkg/resolve).
	QueryType           string // DNS record type to resolve (A, AAAA, ...). Default A.
	BatchMode           string // sendmmsg/recvmmsg batching: off | on | adaptive
	SocketCount         int    // UDP sockets per run (0 = scale to cores)
	UDPSize             int    // EDNS0 advertised UDP payload size (0 = default; <512 disables)
	QPS                 int    // outbound query rate limit (0 = unlimited)
	NoRecurse           bool   // send non-recursive queries (RD=0)
	Sticky              bool   // do not rotate resolver on retry
	ResolverHealth      bool   // per-resolver health scoring / de-weighting
	AdaptiveConcurrency bool   // shrink/grow in-flight cap based on packet loss
	CrossCheck          bool   // re-verify positive answers on a second resolver
	ExtendedInput       bool   // parse "name [resolver ...]" input lines
	NoVerifyIP          bool   // disable reply source-IP verification
	NoTCPFallback       bool   // disable TCP fallback on truncated answers
	// Iterative resolves from the root servers directly (no recursive resolver
	// list needed), caching delegations. Removes the public-resolver dependency.
	Iterative bool

	// Distributed resolution and resume.
	Shard      string // "m/n": process only shard m of n
	ResumeFile string // checkpoint file for crash-safe stop/resume

	OnResult func(*retryabledns.DNSData)
}

func New(options Options) (*Instance, error) {
	var resolvers []string
	if options.TrustedResolvers != "" {
		var err error
		resolvers, err = wildcards.LoadResolversFromFile(options.TrustedResolvers)
		if err != nil {
			return nil, err
		}
	} else {
		resolvers = trustedResolvers
	}

	// Create a resolver and load resolverrs from list
	resolver, err := wildcards.NewResolver(options.Domains, options.Retries, resolvers)
	if err != nil {
		return nil, err
	}

	wildcardStore := wildcards.NewStore()

	instance := &Instance{
		options:          options,
		wildcardStore:    wildcardStore,
		wildcardResolver: resolver,
	}

	return instance, nil
}

// DumpWildcardsToFile dumps all wildcard IPs to the specified file
func (instance *Instance) DumpWildcardsToFile(file string) error {
	return instance.wildcardStore.SaveToFile(file)
}
