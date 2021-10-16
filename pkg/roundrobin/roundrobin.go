package roundrobin

// code adapted from https://github.com/hlts2/round-robin

import (
	"errors"
	"sync/atomic"
)

// ErrNoItems specified for the algorithm
var ErrNoItems = errors.New("no items")

// RoundRobin iterates over the items in a round robin fashion
type RoundRobin struct {
	items []string
	next  uint32
}

// New returns a new RoundRobin structure
func New(items ...string) (*RoundRobin, error) {
	if len(items) == 0 {
		return nil, ErrNoItems
	}

	return &RoundRobin{
		items: items,
	}, nil
}

// Next returns next item
func (r *RoundRobin) Next() string {
	n := atomic.AddUint32(&r.next, 1)
	return r.items[(int(n)-1)%len(r.items)]
}
