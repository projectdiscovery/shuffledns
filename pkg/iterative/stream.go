package iterative

import (
	"context"
	"strings"
	"sync"

	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// StreamConfig wires a bulk iterative resolution.
type StreamConfig struct {
	// OnResult is called for every name that produced a final response
	// (success, NODATA, or NXDOMAIN). Must be concurrency-safe.
	OnResult func(*resolve.Result)
	// OnError is called when a name could not be resolved (no responsive
	// nameserver, loop, context cancelled). Must be concurrency-safe.
	OnError func(name string, err error)
	// QueryType overrides the resolver's default query type for this stream.
	QueryType uint16
}

// ResolveStream consumes names from the channel and resolves them iteratively
// using a pool of Concurrency workers. Every worker reuses a single UDP socket
// and shares the resolver's delegation cache, so cache warmth (root, TLDs,
// popular zones) is amortized across the whole workload. It blocks until the
// input channel is closed and all in-flight work drains, or ctx is cancelled.
func (r *Resolver) ResolveStream(ctx context.Context, names <-chan string, cfg StreamConfig) error {
	qtype := cfg.QueryType
	if qtype == 0 {
		qtype = r.opts.QueryType
	}

	var wg sync.WaitGroup
	wg.Add(r.opts.Concurrency)
	for i := 0; i < r.opts.Concurrency; i++ {
		go func() {
			defer wg.Done()
			ex, err := r.newExchanger()
			if err != nil {
				// a worker that cannot open a socket simply drains its share;
				// other workers continue. Report once per failed name.
				for name := range names {
					if cfg.OnError != nil {
						cfg.OnError(strings.TrimSpace(name), err)
					}
				}
				return
			}
			defer ex.close()
			s := &session{r: r, ex: ex}
			for name := range names {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if ctx.Err() != nil {
					return
				}
				res, rerr := s.resolve(ctx, name, qtype)
				if rerr != nil {
					if cfg.OnError != nil {
						cfg.OnError(name, rerr)
					}
					continue
				}
				if cfg.OnResult != nil {
					cfg.OnResult(res)
				}
			}
		}()
	}
	wg.Wait()
	return ctx.Err()
}
