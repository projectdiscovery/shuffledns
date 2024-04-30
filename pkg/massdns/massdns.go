package massdns

import (
	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
)

type Instance struct {
	options Options

	wildcardStore *wildcards.Store

	wildcardResolver *wildcards.Resolver
}

type Options struct {
	// Domain is the domain specified for enumeration
	Domain string
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

	OnResult func(ip string, hostnames []string)
}

func New(options Options) (*Instance, error) {
	// Create a resolver and load resolverrs from list
	resolver, err := wildcards.NewResolver(options.Domain, options.Retries)
	if err != nil {
		return nil, err
	}

	resolver.AddServersFromList(trustedResolvers)

	wildcardStore := wildcards.NewStore()

	instance := &Instance{
		options:          options,
		wildcardStore:    wildcardStore,
		wildcardResolver: resolver,
	}

	return instance, nil
}
