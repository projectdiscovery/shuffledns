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
