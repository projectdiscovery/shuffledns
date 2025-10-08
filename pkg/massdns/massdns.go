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
	// MassdnsPath is the path to the binary
	MassdnsPath string
	// Threads is the hashmap size for massdns
	Threads int
	// InputFile is the file to use for massdns input
	InputFile string
	// ResolversFile is the file with the resolvers
	ResolversFile string
	// TrustedResolvers is the file with the trusted resolvers
	TrustedResolvers string
	// TempDir is a temporary directory for storing massdns misc files
	TempDir string
	// OutputFile is the file to use for massdns output
	OutputFile string
	// Json is format ouput to ndjson format
	Json bool
	// WildcardsThreads is the number of wildcards concurrent threads
	WildcardsThreads int
	// MassdnsRaw perform wildcards filtering from an existing massdns output file
	MassdnsRaw string
	// StrictWildcard controls whether the wildcard check should be performed on each result
	StrictWildcard bool
	// WildcardOutputFile is the file where the list of wildcards is dumped
	WildcardOutputFile string
	// MassDnsCmd supports massdns flags
	MassDnsCmd string
	// KeepStderr controls whether to capture and store massdns stderr output
	KeepStderr bool
	// BatchSize controls the number of lines per chunk for incremental processing
	BatchSize int

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
