package massdns

import (
	"github.com/projectdiscovery/shuffledns/pkg/store"
	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Client is a client for running massdns on a target
type Client struct {
	config Config

	wildcardIPMap *mapsutil.SyncLockMap[string, struct{}]

	wildcardResolver *wildcards.Resolver
}

// Config contains configuration options for the massdns client
type Config struct {
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

	// todo: this is redundant with the original options struct?
	OnResult func(*store.IPMeta)
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

		wildcardIPMap:    mapsutil.NewSyncLockMap[string, struct{}](),
		wildcardResolver: resolver,
	}, nil
}
