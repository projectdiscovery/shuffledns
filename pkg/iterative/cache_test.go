package iterative

import (
	"testing"
	"time"
)

func TestCanonicalAndParent(t *testing.T) {
	cases := map[string]string{
		"WWW.Example.COM": "www.example.com.",
		"example.com.":    "example.com.",
		"":                ".",
		".":               ".",
	}
	for in, want := range cases {
		if got := canonical(in); got != want {
			t.Errorf("canonical(%q)=%q want %q", in, got, want)
		}
	}
	parents := map[string]string{
		"a.b.c.":       "b.c.",
		"example.com.": "com.",
		"com.":         ".",
		".":            ".",
	}
	for in, want := range parents {
		if got := parentZone(in); got != want {
			t.Errorf("parentZone(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInBailiwick(t *testing.T) {
	yes := [][2]string{{"a.example.com", "example.com"}, {"example.com", "example.com"}, {"x.y.com", "com"}, {"anything", "."}}
	no := [][2]string{{"example.org", "example.com"}, {"com", "example.com"}, {"notexample.com", "example.com"}}
	for _, c := range yes {
		if !inBailiwick(c[0], c[1]) {
			t.Errorf("inBailiwick(%q,%q) = false, want true", c[0], c[1])
		}
	}
	for _, c := range no {
		if inBailiwick(c[0], c[1]) {
			t.Errorf("inBailiwick(%q,%q) = true, want false", c[0], c[1])
		}
	}
}

func TestCacheDeepestAncestor(t *testing.T) {
	c := newCache(1024)
	c.put(&delegation{zone: "com."})
	c.put(&delegation{zone: "example.com."})

	if d := c.best("www.example.com"); d == nil || d.zone != "example.com." {
		t.Fatalf("expected deepest match example.com., got %#v", d)
	}
	if d := c.best("host.other.com"); d == nil || d.zone != "com." {
		t.Fatalf("expected com., got %#v", d)
	}
	if d := c.best("nothing.org"); d != nil {
		t.Fatalf("expected nil for uncached tree, got %#v", d)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := newCache(1024)
	c.put(&delegation{zone: "example.com.", expiry: time.Now().Add(-time.Second)})
	if d := c.best("a.example.com"); d != nil {
		t.Fatalf("expired delegation should not be returned, got %#v", d)
	}
}
