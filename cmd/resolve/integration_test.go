package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/internal/simdns"
	"github.com/projectdiscovery/shuffledns/pkg/output"
	"github.com/projectdiscovery/shuffledns/pkg/ptr"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// TestReversePTRSweepEndToEnd drives the full reverse-PTR pipeline against the
// loopback resolver battery: ptr generator -> native resolver (PTR) -> massdns
// simple output. No traffic leaves the host.
func TestReversePTRSweepEndToEnd(t *testing.T) {
	battery, err := simdns.Start(4, simdns.Config{
		BaseLatency: 200 * time.Microsecond,
		HitPercent:  100,
	})
	if err != nil {
		t.Fatalf("simdns.Start: %v", err)
	}
	defer battery.Stop()

	var buf bytes.Buffer
	w, err := output.NewWriter(&buf, "Snl")
	if err != nil {
		t.Fatal(err)
	}

	client, err := resolve.New(resolve.Options{
		Resolvers:   battery.Addrs,
		QueryType:   dns.TypePTR,
		Concurrency: 1000,
		MaxRetries:  3,
		Timeout:     time.Second,
		OnResult: func(r resolve.Result) {
			_ = w.Write(r)
		},
	})
	if err != nil {
		t.Fatalf("resolve.New: %v", err)
	}
	defer client.Close()

	input := make(chan string, 256)
	go func() {
		defer close(input)
		_ = ptr.Stream(context.Background(), []string{"192.0.2.0/28"}, input)
	}()

	if err := client.Run(context.Background(), input); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = w.Flush()

	out := buf.String()
	// 192.0.2.0/28 = 16 addresses; all resolve (HitPercent 100).
	ptrLines := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " PTR ") {
			ptrLines++
			if !strings.Contains(line, "in-addr.arpa.") || !strings.Contains(line, ".ptr.example.com.") {
				t.Fatalf("unexpected PTR line: %q", line)
			}
		}
	}
	if ptrLines != 16 {
		t.Fatalf("expected 16 PTR answers, got %d in:\n%s", ptrLines, out)
	}
}

// TestCLIAgainstBattery builds the resolve binary and runs it end-to-end against
// the loopback battery, validating flag parsing, stdin input and simple output.
func TestCLIAgainstBattery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}

	battery, err := simdns.Start(4, simdns.Config{BaseLatency: 200 * time.Microsecond, HitPercent: 100})
	if err != nil {
		t.Fatalf("simdns.Start: %v", err)
	}
	defer battery.Stop()

	dir := t.TempDir()
	bin := filepath.Join(dir, "resolve")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	resolversFile := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(resolversFile, []byte(strings.Join(battery.Addrs, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var names strings.Builder
	for i := 0; i < 20; i++ {
		names.WriteString("host")
		names.WriteByte(byte('0' + i%10))
		names.WriteString(".bench.example.com\n")
	}

	cmd := exec.Command(bin, "-r", resolversFile, "-t", "A", "-o", "Snl", "-timeout", "1s")
	cmd.Stdin = strings.NewReader(names.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("resolve binary failed: %v", err)
	}
	if !strings.Contains(string(out), " A 10.") {
		t.Fatalf("expected A-record output, got:\n%s", out)
	}
}

// buildResolve compiles the resolve binary into a temp dir and returns its path.
func buildResolve(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "resolve")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func writeResolversFile(t *testing.T, addrs []string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(f, []byte(strings.Join(addrs, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// resolvedNames extracts the queried names from "Snl" output lines.
func resolvedNames(out string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[1] == "A" {
			set[strings.TrimSuffix(f[0], ".")] = struct{}{}
		}
	}
	return set
}

func benchNames(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "host%d.bench.example.com\n", i)
	}
	return b.String()
}

// TestShardingPartitionsWork runs two shards over the same input and asserts the
// shards resolve disjoint subsets whose union is the full input.
func TestShardingPartitionsWork(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	battery, err := simdns.Start(4, simdns.Config{BaseLatency: 200 * time.Microsecond, HitPercent: 100})
	if err != nil {
		t.Fatalf("simdns.Start: %v", err)
	}
	defer battery.Stop()

	bin := buildResolve(t)
	resolversFile := writeResolversFile(t, battery.Addrs)
	const total = 50
	names := benchNames(total)

	run := func(shard string) map[string]struct{} {
		cmd := exec.Command(bin, "-r", resolversFile, "-t", "A", "-o", "Snl", "-timeout", "1s", "-shard", shard)
		cmd.Stdin = strings.NewReader(names)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("shard %s failed: %v", shard, err)
		}
		return resolvedNames(string(out))
	}

	a := run("1/2")
	b := run("2/2")

	// disjoint
	for n := range a {
		if _, ok := b[n]; ok {
			t.Fatalf("name %q appeared in both shards", n)
		}
	}
	// union == full set
	if len(a)+len(b) != total {
		t.Fatalf("shard union = %d, want %d (a=%d b=%d)", len(a)+len(b), total, len(a), len(b))
	}
	if len(a) == 0 || len(b) == 0 {
		t.Fatalf("a shard got nothing (a=%d b=%d)", len(a), len(b))
	}
}

// TestResumeSkipsCompleted runs once to populate a checkpoint, then re-runs with
// the same checkpoint and asserts everything is skipped.
func TestResumeSkipsCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	battery, err := simdns.Start(4, simdns.Config{BaseLatency: 200 * time.Microsecond, HitPercent: 100})
	if err != nil {
		t.Fatalf("simdns.Start: %v", err)
	}
	defer battery.Stop()

	bin := buildResolve(t)
	resolversFile := writeResolversFile(t, battery.Addrs)
	resumeFile := filepath.Join(t.TempDir(), "resume.log")
	names := benchNames(30)

	run := func() string {
		cmd := exec.Command(bin, "-r", resolversFile, "-t", "A", "-o", "Snl", "-timeout", "1s", "-resume", resumeFile)
		cmd.Stdin = strings.NewReader(names)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
		return string(out)
	}

	first := run()
	if len(resolvedNames(first)) != 30 {
		t.Fatalf("first run resolved %d, want 30", len(resolvedNames(first)))
	}

	second := run()
	if got := len(resolvedNames(second)); got != 0 {
		t.Fatalf("resume run should skip all completed names, but resolved %d", got)
	}
}
