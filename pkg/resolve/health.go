package resolve

import (
	"math"
	"math/rand/v2"
	"sync/atomic"
)

// resolverHealth tracks a smoothed success rate per resolver so that failing or
// rate-limiting resolvers are de-weighted in selection and recover over time.
// This addresses massdns's own TODO of avoiding resolvers that refuse or stop
// answering after a while.
type resolverHealth struct {
	n      int
	weight []atomic.Uint64 // float64 bits, EWMA success in [0,1]; starts at 1.0
}

const (
	healthAlpha     = 0.1 // EWMA smoothing for per-resolver success rate
	healthThreshold = 0.5 // success-rate boundary between healthy and unhealthy
)

func newResolverHealth(n int) *resolverHealth {
	h := &resolverHealth{n: n, weight: make([]atomic.Uint64, n)}
	for i := range h.weight {
		h.weight[i].Store(math.Float64bits(1.0))
	}
	return h
}

func (h *resolverHealth) score(i int) float64 {
	return math.Float64frombits(h.weight[i].Load())
}

// record nudges a resolver's success EWMA toward 1 (answered) or 0 (failed).
// It returns whether the resolver crossed the healthy threshold and the new
// healthy state, so callers can emit state-change events.
func (h *resolverHealth) record(i int, ok bool) (transitioned, healthy bool) {
	if i < 0 || i >= h.n {
		return false, true
	}
	var target float64
	if ok {
		target = 1.0
	}
	for {
		oldBits := h.weight[i].Load()
		old := math.Float64frombits(oldBits)
		nw := old + healthAlpha*(target-old)
		if h.weight[i].CompareAndSwap(oldBits, math.Float64bits(nw)) {
			wasHealthy := old >= healthThreshold
			nowHealthy := nw >= healthThreshold
			return wasHealthy != nowHealthy, nowHealthy
		}
	}
}

// pick selects a resolver using the power-of-two-choices: sample two at random
// and keep the healthier one. This is lock-free, needs no running totals, and
// naturally steers load away from unhealthy resolvers while still probing them
// occasionally (so they can recover).
func (h *resolverHealth) pick() int {
	if h.n == 1 {
		return 0
	}
	a := rand.IntN(h.n)
	b := rand.IntN(h.n)
	if h.score(b) > h.score(a) {
		return b
	}
	return a
}
