package massdns

import (
	"sync"

	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
)

// Client is a client for running massdns on a target
type Client struct {
	config Config

	wildcardIPMap   map[string]struct{}
	wildcardIPMutex *sync.RWMutex

	wildcardResolver *wildcards.Resolver
}

// Config contains configuration options for the massdns client
type Config struct {
	// Domain is the domain specified for enumeration
	Domain string
	// Retries is the nmber of retries for dns
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
	// WildcardsThreads is the number of wildcards concurrent threads
	WildcardsThreads int
	// MassdnsRaw perform wildcards filtering from an existing massdns output file
	MassdnsRaw string
	// StrictWildcard controls whether the wildcard check should be performed on each result
	StrictWildcard bool
}

// excellentResolvers contains some resolvers used in dns verification step
var excellentResolvers = []string{
	"1.1.1.1",
	"1.0.0.1",
	"8.8.8.8",
	"8.8.4.4",
}

// New returns a new massdns client for running enumeration
// on a target.
func New(config Config) (*Client, error) {
	// Create a resolver and load resolverrs from list
	resolver, err := wildcards.NewResolver(config.Domain, config.Retries)
	if err != nil {
		return nil, err
	}
	resolver.AddServersFromList(excellentResolvers)

	return &Client{
		config: config,

		wildcardIPMap:    make(map[string]struct{}),
		wildcardIPMutex:  &sync.RWMutex{},
		wildcardResolver: resolver,
	}, nil
}
