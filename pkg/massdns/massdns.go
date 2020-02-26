package massdns

import (
	"sync"

	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
)

// Client is a client for running massdns on a target
type Client struct {
	massDNSPath  string
	outputFolder string

	wildcardIPMap   map[string]struct{}
	wildcardIPMutex *sync.RWMutex

	wildcardResolvers *wildcards.Resolver
}

// Config contains configuration options for the massdns client
type Config struct {
}

// New returns a new massdns client for running enumeration
// on a target.
func New() (*Client, error) {

}
