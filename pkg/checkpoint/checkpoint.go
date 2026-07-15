// Package checkpoint provides crash-safe stop/resume for long resolution runs.
//
// The model is an append-only log of completed names. A name is "completed" once
// it reaches a terminal state (an answer or a definitive give-up), at which point
// the consumer calls Done. On a later run, Open replays the log so the producer
// can skip names that already finished via Has.
//
// Semantics are at-least-once: only names recorded as done are skipped, so any
// name that was in flight when the process died is simply re-resolved on resume.
// Nothing is ever lost (no false negatives); at worst a small in-flight window is
// repeated, which is harmless because downstream dedup absorbs it.
package checkpoint

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// flushEvery bounds how many completions buffer before a forced flush, so a
// crash loses at most this many log records (which are re-resolved anyway).
const flushEvery = 1024

// Checkpoint is a resumable completed-name log. It is safe for concurrent use.
type Checkpoint struct {
	mu      sync.Mutex
	done    map[string]struct{}
	f       *os.File
	w       *bufio.Writer
	pending int
	closed  bool
}

// Open opens (creating if needed) the checkpoint at path and loads any previously
// completed names from it. Subsequent writes append to the same file.
func Open(path string) (*Checkpoint, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("checkpoint path is required")
	}
	c := &Checkpoint{done: make(map[string]struct{})}

	// load existing entries (resume)
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				c.done[line] = struct{}{}
			}
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("could not read checkpoint: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not open checkpoint: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("could not open checkpoint for append: %w", err)
	}
	c.f = f
	c.w = bufio.NewWriterSize(f, 64*1024)
	return c, nil
}

// Resumed reports the number of completed names loaded from a prior run.
func (c *Checkpoint) Resumed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.done)
}

// Has reports whether name already completed in this or a prior run.
func (c *Checkpoint) Has(name string) bool {
	c.mu.Lock()
	_, ok := c.done[name]
	c.mu.Unlock()
	return ok
}

// Done records name as completed. It returns false if the name was already
// recorded (so callers can detect duplicates). Records are buffered and flushed
// periodically; Close guarantees durability of everything recorded.
func (c *Checkpoint) Done(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if _, ok := c.done[name]; ok {
		return false
	}
	c.done[name] = struct{}{}
	_, _ = c.w.WriteString(name)
	_ = c.w.WriteByte('\n')
	c.pending++
	if c.pending >= flushEvery {
		_ = c.w.Flush()
		c.pending = 0
	}
	return true
}

// Flush flushes buffered records to disk.
func (c *Checkpoint) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.pending = 0
	return c.w.Flush()
}

// Close flushes and closes the underlying file.
func (c *Checkpoint) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if err := c.w.Flush(); err != nil {
		_ = c.f.Close()
		return err
	}
	return c.f.Close()
}

// FlushPeriodically flushes the log on the given interval until stop is closed.
// Useful for bounding data loss on a crash during very long, low-completion runs.
func (c *Checkpoint) FlushPeriodically(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = c.Flush()
		}
	}
}
