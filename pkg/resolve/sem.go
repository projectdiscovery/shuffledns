package resolve

import (
	"context"
	"sync"
)

// adaptiveSem is a counting semaphore whose capacity can be changed at runtime.
// It is used for the adaptive-concurrency in-flight cap: the controller shrinks
// the cap under packet loss (to stop flooding a saturated resolver) and grows
// it back when loss subsides. Acquire is cancellable via context.
//
// Only one goroutine acquires (the dispatcher) while many release (readers and
// timeout/fallback paths), so the single mutex sees low contention.
type adaptiveSem struct {
	mu     sync.Mutex
	cond   *sync.Cond
	cur    int
	cap    int
	maxCap int
	closed bool
}

func newAdaptiveSem(capacity int) *adaptiveSem {
	if capacity < 1 {
		capacity = 1
	}
	s := &adaptiveSem{cur: 0, cap: capacity, maxCap: capacity}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// watch wires context cancellation to wake any blocked acquirers.
func (s *adaptiveSem) watch(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.cond.Broadcast()
	}()
}

func (s *adaptiveSem) acquire(ctx context.Context) error {
	s.mu.Lock()
	for s.cur >= s.cap && !s.closed {
		s.cond.Wait()
	}
	if s.closed {
		s.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.Canceled
	}
	s.cur++
	s.mu.Unlock()
	return nil
}

func (s *adaptiveSem) release() {
	s.mu.Lock()
	if s.cur > 0 {
		s.cur--
	}
	s.mu.Unlock()
	s.cond.Signal()
}

// setCap adjusts the capacity, clamped to [1, maxCap]. Increasing it wakes
// waiters so they can proceed immediately.
func (s *adaptiveSem) setCap(n int) {
	if n < 1 {
		n = 1
	}
	s.mu.Lock()
	if n > s.maxCap {
		n = s.maxCap
	}
	grew := n > s.cap
	s.cap = n
	s.mu.Unlock()
	if grew {
		s.cond.Broadcast()
	}
}

func (s *adaptiveSem) capacity() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cap
}

func (s *adaptiveSem) inflight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}
