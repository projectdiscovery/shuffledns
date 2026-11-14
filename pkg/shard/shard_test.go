package shard

import (
	"fmt"
	"testing"
)

func TestParse(t *testing.T) {
	cases := map[string]struct {
		idx, total int
		err        bool
	}{
		"":      {1, 1, false},
		"1/1":   {1, 1, false},
		"2/8":   {2, 8, false},
		"8/8":   {8, 8, false},
		"0/8":   {0, 0, true},
		"9/8":   {0, 0, true},
		"2/0":   {0, 0, true},
		"x/8":   {0, 0, true},
		"2":     {0, 0, true},
		"2/3/4": {0, 0, true},
	}
	for in, want := range cases {
		got, err := Parse(in)
		if want.err {
			if err == nil {
				t.Errorf("Parse(%q): expected error", in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error %v", in, err)
			continue
		}
		if got.Index != want.idx || got.Total != want.total {
			t.Errorf("Parse(%q): got %d/%d want %d/%d", in, got.Index, got.Total, want.idx, want.total)
		}
	}
}

func TestEnabled(t *testing.T) {
	if (Shard{1, 1}).Enabled() {
		t.Fatal("1/1 should be disabled")
	}
	if !(Shard{1, 4}).Enabled() {
		t.Fatal("1/4 should be enabled")
	}
}

func TestDisabledOwnsEverything(t *testing.T) {
	s := Shard{1, 1}
	for i := 0; i < 100; i++ {
		if !s.Owns(fmt.Sprintf("host%d.example.com", i)) {
			t.Fatal("disabled shard must own every key")
		}
	}
}

// TestPartitionExactlyOnce is the core guarantee: across N shards every name is
// owned by exactly one shard.
func TestPartitionExactlyOnce(t *testing.T) {
	const total = 8
	shards := make([]Shard, total)
	for i := range shards {
		shards[i] = Shard{Index: i + 1, Total: total}
	}
	counts := make([]int, total)
	for i := 0; i < 10000; i++ {
		name := fmt.Sprintf("sub-%d.target.com", i)
		owners := 0
		for j, s := range shards {
			if s.Owns(name) {
				owners++
				counts[j]++
			}
		}
		if owners != 1 {
			t.Fatalf("name %q owned by %d shards, want 1", name, owners)
		}
	}
	// sanity: distribution should be roughly even (no empty shard)
	for j, c := range counts {
		if c == 0 {
			t.Fatalf("shard %d got no names (bad distribution)", j+1)
		}
	}
}

func TestStableAcrossCase(t *testing.T) {
	s := Shard{Index: 3, Total: 8}
	if s.Owns("Host.EXAMPLE.com") != s.Owns("host.example.com") {
		t.Fatal("ownership must be case-insensitive/stable")
	}
}
