package checkpoint

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestDoneAndHas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.log")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Has("a.com") {
		t.Fatal("fresh checkpoint should not have anything")
	}
	if !c.Done("a.com") {
		t.Fatal("first Done should report newly-completed")
	}
	if c.Done("a.com") {
		t.Fatal("second Done should report already-completed")
	}
	if !c.Has("a.com") {
		t.Fatal("Has should see completed name")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.log")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.com", "b.com", "c.com"} {
		c.Done(n)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// reopen: prior completions must be visible
	c2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Resumed() != 3 {
		t.Fatalf("expected 3 resumed, got %d", c2.Resumed())
	}
	for _, n := range []string{"a.com", "b.com", "c.com"} {
		if !c2.Has(n) {
			t.Fatalf("resumed checkpoint missing %q", n)
		}
	}
	if c2.Has("d.com") {
		t.Fatal("should not have uncompleted name")
	}
}

// TestCrashSafety simulates a crash (no Close) after enough completions to force
// at least one buffer flush; those must survive on reopen.
func TestCrashSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.log")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = flushEvery + 10
	for i := 0; i < n; i++ {
		c.Done(itoa(i))
	}
	// no Close(): only flushed records (>= flushEvery) are guaranteed durable.
	c2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Resumed() < flushEvery {
		t.Fatalf("expected at least %d durable records, got %d", flushEvery, c2.Resumed())
	}
}

func TestConcurrentDone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.log")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				c.Done(itoa(g*1000 + i))
			}
		}(g)
	}
	wg.Wait()
	if got := c.Resumed(); got != 8000 {
		t.Fatalf("expected 8000 unique completions, got %d", got)
	}
}

func TestOpenRequiresPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return "host-" + string(b[pos:])
}
