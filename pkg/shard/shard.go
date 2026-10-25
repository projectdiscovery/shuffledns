// Package shard implements deterministic workload sharding for distributed,
// coordinated resolution. Running N instances each with a distinct shard
// (1/N .. N/N) over the same input partitions the work into disjoint subsets
// with no central coordinator: every instance independently decides which names
// it owns via a stable hash, so the union covers the input exactly once.
//
// This mirrors masscan-style sharding but for DNS names: because names cannot be
// split arithmetically like an address range, each instance reads the full input
// and cheaply hashes every candidate to decide ownership.
package shard

import (
	"fmt"
	"strconv"
	"strings"
)

// Shard identifies one partition (Index) out of Total. Index is 1-based and in
// the range [1, Total], matching the "m/n" convention.
type Shard struct {
	Index int
	Total int
}

// Parse parses an "m/n" shard specification (e.g. "2/8"). An empty string or
// "1/1" yields a disabled shard that owns everything.
func Parse(s string) (Shard, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Shard{Index: 1, Total: 1}, nil
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return Shard{}, fmt.Errorf("invalid shard %q: expected m/n", s)
	}
	idx, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	total, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return Shard{}, fmt.Errorf("invalid shard %q: m and n must be integers", s)
	}
	sh := Shard{Index: idx, Total: total}
	if err := sh.Validate(); err != nil {
		return Shard{}, err
	}
	return sh, nil
}

// Validate checks the shard is internally consistent.
func (s Shard) Validate() error {
	if s.Total < 1 {
		return fmt.Errorf("shard total must be >= 1, got %d", s.Total)
	}
	if s.Index < 1 || s.Index > s.Total {
		return fmt.Errorf("shard index %d out of range [1,%d]", s.Index, s.Total)
	}
	return nil
}

// Enabled reports whether sharding actually partitions the input (Total > 1).
func (s Shard) Enabled() bool { return s.Total > 1 }

// Owns reports whether this shard is responsible for key. When sharding is
// disabled it always returns true. The hash is a stable FNV-1a over the
// lower-cased key, so the partitioning is identical across machines, runs and
// architectures.
func (s Shard) Owns(key string) bool {
	if !s.Enabled() {
		return true
	}
	return Bucket(key, s.Total) == s.Index-1
}

// Bucket returns the stable bucket index in [0, total) for key, using FNV-1a
// over the lower-cased key. Implemented inline (no hash.Hash allocation) so it
// stays cheap when called once per candidate name.
func Bucket(key string, total int) int {
	if total <= 1 {
		return 0
	}
	const (
		offset64 = 14695981039346656037 // FNV-1a 64-bit offset basis
		prime64  = 1099511628211        // FNV-1a 64-bit prime
	)
	var h uint64 = offset64
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= prime64
	}
	return int(h % uint64(total))
}
