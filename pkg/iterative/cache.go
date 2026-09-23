package iterative

import (
	"net"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// nsEntry is a single nameserver of a delegation: its name plus any glue
// addresses learned from the parent zone (empty when the delegation is
// glueless and the address must be resolved separately).
type nsEntry struct {
	name  string
	addrs []net.IP
}

// delegation is the set of nameservers authoritative for (or one step closer
// to) a zone, as learned from a referral. It is the unit cached and shared
// across all in-flight resolutions, which is what amortizes the cost of
// re-walking root/TLD for every name (the key win over a per-name resolver).
type delegation struct {
	zone   string    // canonical zone (lowercase, trailing dot)
	ns     []nsEntry // nameservers, some possibly with glue
	expiry time.Time // zero == never expires (root hints)
}

func (d *delegation) expired(now time.Time) bool {
	return !d.expiry.IsZero() && now.After(d.expiry)
}

// cache is a bounded, TTL-aware store of delegations keyed by canonical zone.
// It is safe for concurrent use (the underlying LRU is locked) and shared by
// every worker so that common ancestors (root, TLDs, popular zones) are walked
// once and reused.
type cache struct {
	lru *lru.Cache[string, *delegation]
}

func newCache(size int) *cache {
	if size <= 0 {
		size = 1 << 16
	}
	l, _ := lru.New[string, *delegation](size)
	return &cache{lru: l}
}

func (c *cache) put(d *delegation) {
	if d == nil || d.zone == "" {
		return
	}
	c.lru.Add(canonical(d.zone), d)
}

// best returns the deepest (closest to name) non-expired cached delegation,
// walking ancestor labels of name. It returns nil when nothing is cached.
func (c *cache) best(name string) *delegation {
	now := time.Now()
	for z := canonical(name); ; z = parentZone(z) {
		if d, ok := c.lru.Get(z); ok {
			if d.expired(now) {
				c.lru.Remove(z)
			} else {
				return d
			}
		}
		if z == "." {
			return nil
		}
	}
}

// canonical lowercases a name and ensures a single trailing dot. The root is ".".
func canonical(name string) string {
	if name == "" || name == "." {
		return "."
	}
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// parentZone returns the parent of a canonical zone ("a.b.c." -> "b.c."); the
// parent of a TLD (or root) is the root ".".
func parentZone(zone string) string {
	if zone == "." || zone == "" {
		return "."
	}
	zone = strings.TrimSuffix(zone, ".")
	i := strings.IndexByte(zone, '.')
	if i < 0 {
		return "."
	}
	return zone[i+1:] + "."
}

// inBailiwick reports whether child is equal to or a subdomain of parent. It is
// used to reject out-of-bailiwick referrals and glue (a core anti-poisoning
// check): an authority can only delegate names within its own zone.
func inBailiwick(child, parent string) bool {
	child, parent = canonical(child), canonical(parent)
	if parent == "." {
		return true
	}
	return child == parent || strings.HasSuffix(child, "."+parent)
}
