package resolve

import (
	"context"
	"time"
)

// limiter is a simple token-bucket rate limiter that refills at a fixed QPS.
// take() blocks until a token is available. It is intentionally lightweight to
// avoid a hard dependency while keeping outbound query rate bounded.
type limiter struct {
	tokens chan struct{}
	qps    int
	stopCh chan struct{}
}

func newLimiter(qps int) *limiter {
	if qps <= 0 {
		return nil
	}
	// burst capacity of one second worth of tokens, capped for memory sanity
	burst := qps
	if burst > 100000 {
		burst = 100000
	}
	return &limiter{
		tokens: make(chan struct{}, burst),
		qps:    qps,
		stopCh: make(chan struct{}),
	}
}

func (l *limiter) start(ctx context.Context) {
	// refill in small slices to smooth out bursts
	slices := 100
	perTick := l.qps / slices
	if perTick < 1 {
		perTick = 1
		slices = l.qps
	}
	interval := time.Second / time.Duration(slices)
	if interval <= 0 {
		interval = time.Millisecond
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-l.stopCh:
				return
			case <-ticker.C:
				for i := 0; i < perTick; i++ {
					select {
					case l.tokens <- struct{}{}:
					default:
						// bucket full
					}
				}
			}
		}
	}()
}

func (l *limiter) take() {
	<-l.tokens
}

func (l *limiter) stop() {
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
}
