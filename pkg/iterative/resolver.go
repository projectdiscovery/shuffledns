// Package iterative implements a high-throughput iterative DNS resolver that
// recurses from the root servers itself, caching delegations (NS + glue) in a
// shared, bounded cache. Unlike a stub resolver it does not depend on
// third-party recursive resolvers, which is the root cause of the
// false-negative / poisoning problems that plague large bruteforce runs: there
// is no resolver list to curate, no rate-limited public resolver returning a
// bogus NOERROR/NXDOMAIN, and every answer comes straight from the zone's
// authoritative servers.
//
// The cache is the performance lever. The first name in a zone walks
// root -> TLD -> authoritative; every subsequent name in that zone (or any
// already-seen ancestor) reuses the cached delegation and costs a single round
// trip to the authoritative server. Across a typical bruteforce workload (many
// names under few registrable domains) this collapses to ~1 query per name
// after warmup.
//
// Anti-poisoning: referrals and glue are accepted only when in-bailiwick (a
// server may only delegate names within its own zone), responses are matched
// by transaction id + question, and replies are accepted only from the address
// the query was sent to.
package iterative

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// Resolver errors.
var (
	ErrMaxReferrals = errors.New("iterative: too many referral hops")
	ErrMaxDepth     = errors.New("iterative: max recursion depth exceeded")
	ErrNoNameserver = errors.New("iterative: no responsive nameserver for zone")
	ErrCNAMELoop    = errors.New("iterative: CNAME loop detected")
)

// QueryInfo describes a single authoritative query for the hooks.
type QueryInfo struct {
	Name   string // name being looked up (no trailing dot)
	Type   uint16
	Zone   string // delegation zone the query targets
	Server string // nameserver address (ip:port)
	Depth  int    // glue-resolution recursion depth
}

// Hooks are optional observation points for SDK/observability use. All may be
// nil. They fire on the resolution path and must be cheap and concurrency-safe.
type Hooks struct {
	// OnQuery fires before each authoritative query is sent.
	OnQuery func(QueryInfo)
	// OnReferral fires when a referral is accepted and cached (descending a level).
	OnReferral func(parentZone, childZone string, ns []string)
	// OnCacheHit fires when resolution starts from a cached delegation (not root).
	OnCacheHit func(name, zone string)
	// OnResponse fires for every accepted authoritative response (read-only).
	OnResponse func(QueryInfo, *dns.Msg)
}

// Options configures the iterative resolver.
type Options struct {
	// QueryType is the record type to resolve (default dns.TypeA).
	QueryType uint16
	// Timeout is the per-attempt query timeout (default 3s).
	Timeout time.Duration
	// Retries is the number of UDP retransmits to the same server before
	// moving to the next nameserver (default 2).
	Retries int
	// Concurrency is the number of parallel workers for ResolveStream
	// (default 100). Each worker reuses a single UDP socket.
	Concurrency int
	// MaxReferrals caps referral hops per name (loop guard, default 30).
	MaxReferrals int
	// MaxDepth caps nested glue-resolution recursion (default 8).
	MaxDepth int
	// UDPSize is the EDNS0 advertised payload size (default 1232). <512 disables EDNS0.
	UDPSize int
	// IPv6 enables using IPv6 glue and transport in addition to IPv4.
	IPv6 bool
	// DisableTCPFallback disables retrying truncated (TC) answers over TCP.
	DisableTCPFallback bool
	// CacheSize bounds the delegation cache (default 65536 zones).
	CacheSize int
	// Port is the destination port for nameservers (default 53). Overridable
	// for testing against a loopback hierarchy.
	Port int
	// RootServers overrides the built-in root hints with "ip" or "ip:port"
	// addresses (testing / split-horizon roots).
	RootServers []string
	// Hooks holds optional lifecycle callbacks.
	Hooks Hooks
}

func (o *Options) setDefaults() {
	if o.QueryType == 0 {
		o.QueryType = dns.TypeA
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Retries < 0 {
		o.Retries = 0
	} else if o.Retries == 0 {
		o.Retries = 2
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 100
	}
	if o.MaxReferrals <= 0 {
		o.MaxReferrals = 30
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 8
	}
	if o.UDPSize == 0 {
		o.UDPSize = 1232
	}
	if o.CacheSize <= 0 {
		o.CacheSize = 1 << 16
	}
	if o.Port <= 0 {
		o.Port = 53
	}
}

// exchanger performs a single query/response with one nameserver. The default
// implementation uses UDP with TCP fallback; tests inject an in-memory hierarchy.
type exchanger interface {
	exchange(ctx context.Context, server netip.AddrPort, msg *dns.Msg) (*dns.Msg, error)
	close()
}

// Resolver is a shared, concurrency-safe iterative resolver. Create one with
// New and reuse it across many names; the delegation cache is shared by all
// resolutions and is what makes repeated lookups cheap.
type Resolver struct {
	opts  Options
	cache *cache
	root  *delegation

	// newExchanger builds a per-worker exchanger (own socket). Overridable in tests.
	newExchanger func() (exchanger, error)
}

// New creates a Resolver with the given options.
func New(opts Options) (*Resolver, error) {
	opts.setDefaults()
	r := &Resolver{
		opts:  opts,
		cache: newCache(opts.CacheSize),
	}
	r.root = r.buildRoot()
	r.newExchanger = func() (exchanger, error) { return newUDPExchanger(&r.opts) }
	return r, nil
}

func (r *Resolver) buildRoot() *delegation {
	if len(r.opts.RootServers) == 0 {
		return defaultRootDelegation(r.opts.IPv6)
	}
	// Custom roots (testing / split-horizon). Accept "ip" or "ip:port"; an
	// explicit port overrides the resolver's default port (last one wins, and
	// custom root sets are normally uniform).
	d := &delegation{zone: "."}
	for i, s := range r.opts.RootServers {
		host := s
		if ap, err := netip.ParseAddrPort(s); err == nil {
			host = ap.Addr().String()
			r.opts.Port = int(ap.Port())
		}
		ip := net.ParseIP(host)
		ns := nsEntry{name: fmt.Sprintf("root-%d.", i)}
		if ip != nil {
			ns.addrs = append(ns.addrs, ip)
		}
		d.ns = append(d.ns, ns)
	}
	return d
}

// addrPort converts a glue IP to a netip.AddrPort using the resolver's port.
func (r *Resolver) addrPort(ip net.IP) (netip.AddrPort, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	a = a.Unmap()
	if a.Is6() && !r.opts.IPv6 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, uint16(r.opts.Port)), true
}

// Resolve performs a one-off iterative resolution of name/qtype. For bulk work
// prefer ResolveStream, which reuses sockets and shares cache warmth across a
// pool of workers.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (*resolve.Result, error) {
	if qtype == 0 {
		qtype = r.opts.QueryType
	}
	ex, err := r.newExchanger()
	if err != nil {
		return nil, err
	}
	defer ex.close()
	s := &session{r: r, ex: ex}
	return s.resolve(ctx, name, qtype)
}

// session is a single worker's resolution context: it owns one exchanger
// (socket) reused across the sequential queries a resolution requires.
type session struct {
	r  *Resolver
	ex exchanger
}

func (s *session) resolve(ctx context.Context, name string, qtype uint16) (*resolve.Result, error) {
	return s.resolveDepth(ctx, name, qtype, 0, map[string]struct{}{})
}

func (s *session) resolveDepth(ctx context.Context, name string, qtype uint16, depth int, cnameSeen map[string]struct{}) (*resolve.Result, error) {
	if depth > s.r.opts.MaxDepth {
		return nil, ErrMaxDepth
	}
	sname := canonical(name)

	del := s.r.cache.best(sname)
	if del == nil {
		del = s.r.root
	} else if s.r.opts.Hooks.OnCacheHit != nil {
		s.r.opts.Hooks.OnCacheHit(strings.TrimSuffix(sname, "."), del.zone)
	}
	zone := del.zone

	var cnameChain []string

	for hops := 0; hops < s.r.opts.MaxReferrals; hops++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, server, err := s.queryZone(ctx, del, zone, sname, qtype, depth)
		if err != nil {
			return nil, err
		}
		if s.r.opts.Hooks.OnResponse != nil {
			s.r.opts.Hooks.OnResponse(QueryInfo{Name: strings.TrimSuffix(sname, "."), Type: qtype, Zone: zone, Server: server, Depth: depth}, resp)
		}

		// definitive negative
		if resp.Rcode == dns.RcodeNameError {
			return buildResult(name, qtype, resp, server, cnameChain), nil
		}

		// follow any CNAME chain present in this answer
		final, cnames := chaseCNAME(resp.Answer, sname)
		if len(cnames) > 0 {
			cnameChain = append(cnameChain, cnames...)
		}

		// direct answer of the requested type for the (possibly chased) name?
		if answersType(resp.Answer, final, qtype) {
			return buildResult(name, qtype, resp, server, cnameChain), nil
		}

		// CNAME points outside what this answer resolves: restart for the target.
		if final != sname && qtype != dns.TypeCNAME && qtype != dns.TypeANY {
			if _, seen := cnameSeen[final]; seen {
				return nil, ErrCNAMELoop
			}
			cnameSeen[final] = struct{}{}
			sub, err := s.resolveDepth(ctx, final, qtype, depth+1, cnameSeen)
			if err != nil {
				return nil, err
			}
			return mergeCNAME(name, qtype, cnameChain, server, sub), nil
		}

		// referral to a closer zone?
		if child := s.parseReferral(resp, zone, sname); child != nil {
			s.r.cache.put(child)
			if s.r.opts.Hooks.OnReferral != nil {
				s.r.opts.Hooks.OnReferral(zone, child.zone, nsNames(child))
			}
			del = child
			zone = child.zone
			continue
		}

		// NOERROR with no answer and no usable referral == NODATA (name exists,
		// type doesn't) or an empty/lame response we can't progress past.
		return buildResult(name, qtype, resp, server, cnameChain), nil
	}
	return nil, ErrMaxReferrals
}

// queryZone tries the nameservers of a delegation until one returns a usable
// response. Glueless nameservers have their addresses resolved on demand.
func (s *session) queryZone(ctx context.Context, del *delegation, zone, sname string, qtype uint16, depth int) (*dns.Msg, string, error) {
	order := rand.Perm(len(del.ns))

	// first pass: nameservers that already have glue (no extra round trips)
	for _, gluedOnly := range []bool{true, false} {
		for _, idx := range order {
			ns := del.ns[idx]
			addrs := ns.addrs
			if len(addrs) == 0 {
				if gluedOnly {
					continue
				}
				// glueless: resolve the nameserver's address from the root.
				addrs = s.resolveNSAddrs(ctx, ns.name, depth)
				if len(addrs) == 0 {
					continue
				}
			} else if !gluedOnly {
				// already tried in the glued pass
				continue
			}
			for _, ip := range addrs {
				ap, ok := s.r.addrPort(ip)
				if !ok {
					continue
				}
				if s.r.opts.Hooks.OnQuery != nil {
					s.r.opts.Hooks.OnQuery(QueryInfo{Name: strings.TrimSuffix(sname, "."), Type: qtype, Zone: zone, Server: ap.String(), Depth: depth})
				}
				resp, err := s.ex.exchange(ctx, ap, s.newQuery(sname, qtype))
				if err != nil {
					continue
				}
				return resp, ap.String(), nil
			}
		}
	}
	return nil, "", ErrNoNameserver
}

// resolveNSAddrs resolves the A (and AAAA when enabled) addresses of a glueless
// nameserver, bounded by depth to prevent runaway recursion.
func (s *session) resolveNSAddrs(ctx context.Context, nsName string, depth int) []net.IP {
	if depth+1 > s.r.opts.MaxDepth {
		return nil
	}
	var out []net.IP
	if res, err := s.resolveDepth(ctx, nsName, dns.TypeA, depth+1, map[string]struct{}{}); err == nil {
		for _, a := range res.A {
			if ip := net.ParseIP(a); ip != nil {
				out = append(out, ip)
			}
		}
	}
	if s.r.opts.IPv6 {
		if res, err := s.resolveDepth(ctx, nsName, dns.TypeAAAA, depth+1, map[string]struct{}{}); err == nil {
			for _, a := range res.AAAA {
				if ip := net.ParseIP(a); ip != nil {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

// newQuery builds an iterative (RD=0) query message with EDNS0.
func (s *session) newQuery(sname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = []dns.Question{{Name: sname, Qtype: qtype, Qclass: dns.ClassINET}}
	if s.r.opts.UDPSize >= 512 {
		m.SetEdns0(uint16(s.r.opts.UDPSize), false)
	}
	return m
}

// parseReferral extracts a closer, in-bailiwick delegation from a response's
// authority (NS) and additional (glue) sections. Returns nil when the response
// is not a usable referral (no NS, out-of-bailiwick, or not closer than zone).
func (s *session) parseReferral(resp *dns.Msg, parentZone, sname string) *delegation {
	var child string
	nsByOwner := map[string][]string{}
	var minTTL uint32 = 0xffffffff
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := canonical(ns.Header().Name)
		// the referral zone must be within the parent and a strict descendant
		// (progress), and an ancestor of the queried name.
		if !inBailiwick(owner, parentZone) || owner == canonical(parentZone) {
			continue
		}
		if !inBailiwick(sname, owner) {
			continue
		}
		child = owner
		nsByOwner[owner] = append(nsByOwner[owner], canonical(ns.Ns))
		if ns.Header().Ttl < minTTL {
			minTTL = ns.Header().Ttl
		}
	}
	if child == "" {
		return nil
	}

	// collect in-bailiwick glue for the chosen child's nameservers
	glue := map[string][]net.IP{}
	for _, rr := range resp.Extra {
		var name string
		var ip net.IP
		switch a := rr.(type) {
		case *dns.A:
			name, ip = canonical(a.Header().Name), a.A
		case *dns.AAAA:
			if !s.r.opts.IPv6 {
				continue
			}
			name, ip = canonical(a.Header().Name), a.AAAA
		default:
			continue
		}
		// accept glue only within the parent zone's bailiwick (anti-poisoning).
		if !inBailiwick(name, parentZone) {
			continue
		}
		glue[name] = append(glue[name], ip)
	}

	d := &delegation{zone: child}
	if minTTL == 0xffffffff || minTTL < 1 {
		minTTL = 60
	}
	d.expiry = time.Now().Add(time.Duration(minTTL) * time.Second)
	for _, nsname := range nsByOwner[child] {
		d.ns = append(d.ns, nsEntry{name: nsname, addrs: glue[nsname]})
	}
	if len(d.ns) == 0 {
		return nil
	}
	return d
}

func nsNames(d *delegation) []string {
	out := make([]string, 0, len(d.ns))
	for _, ns := range d.ns {
		out = append(out, ns.name)
	}
	return out
}
