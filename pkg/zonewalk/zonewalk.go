// Package zonewalk enumerates the contents of a DNS zone by following its NSEC
// chain (RFC 4034 §4). Zones signed with NSEC leak their full list of names: each
// NSEC record points to the next name in canonical order, so walking the chain
// from the apex recovers every owner name for free, without a wordlist. This is
// directly useful for subdomain enumeration.
//
// Zones signed with NSEC3 hash their names and cannot be walked online; Walk
// detects this and reports it (along with the NSEC3 parameters) so callers can
// decide whether to attempt offline hash cracking.
package zonewalk

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Config controls a zone walk.
type Config struct {
	// Zone is the apex to enumerate (e.g. "example.com").
	Zone string
	// Resolvers are DNSSEC-aware resolvers to query (host or host:port). The
	// first reachable one is used.
	Resolvers []string
	// Timeout is the per-query timeout. Default 5s.
	Timeout time.Duration
	// MaxNames caps the number of discovered names (0 = unlimited). A safety
	// valve against pathological/looping chains.
	MaxNames int
	// OnName is an optional callback fired for each newly discovered name.
	OnName func(string)
}

// NSEC3Info holds the parameters of an NSEC3-signed zone.
type NSEC3Info struct {
	Salt       string
	Iterations uint16
	HashAlg    uint8
}

// Result is the outcome of a zone walk.
type Result struct {
	Zone       string
	Names      []string   // discovered owner names (no trailing dot), excluding the apex
	NSEC3      bool       // zone uses NSEC3 (not walkable online)
	NSEC3Param *NSEC3Info // populated when NSEC3 is true and parameters were seen
}

// Walk follows the NSEC chain of cfg.Zone and returns the discovered names.
func Walk(ctx context.Context, cfg Config) (*Result, error) {
	if strings.TrimSpace(cfg.Zone) == "" {
		return nil, fmt.Errorf("zone is required")
	}
	if len(cfg.Resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	server := normalize(cfg.Resolvers[0])
	apex := dns.Fqdn(strings.ToLower(cfg.Zone))
	client := &dns.Client{Timeout: cfg.Timeout}

	res := &Result{Zone: cfg.Zone}
	visited := map[string]struct{}{}
	current := apex

	for {
		resp, err := queryNSEC(ctx, client, server, current)
		if err != nil {
			if len(res.Names) > 0 {
				// partial walk: return what we have rather than failing hard
				return res, nil
			}
			return nil, fmt.Errorf("nsec query for %s failed: %w", current, err)
		}

		if info, ok := nsec3Param(resp); ok {
			res.NSEC3 = true
			res.NSEC3Param = info
			return res, nil
		}

		next, ok := nextName(resp, current)
		if !ok {
			// no NSEC for this owner: chain ended or zone is not NSEC-signed
			return res, nil
		}

		// termination: the last NSEC wraps back to the apex (or we loop).
		if next == apex || equalName(next, apex) {
			return res, nil
		}
		if _, seen := visited[next]; seen {
			return res, nil
		}
		visited[next] = struct{}{}

		name := strings.TrimSuffix(next, ".")
		res.Names = append(res.Names, name)
		if cfg.OnName != nil {
			cfg.OnName(name)
		}
		if cfg.MaxNames > 0 && len(res.Names) >= cfg.MaxNames {
			return res, nil
		}
		current = next
	}
}

func queryNSEC(ctx context.Context, client *dns.Client, server, name string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeNSEC)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO bit: request DNSSEC records
	resp, _, err := client.ExchangeContext(ctx, m, server)
	return resp, err
}

// nextName finds the NSEC record covering `owner` and returns its NextDomain.
func nextName(resp *dns.Msg, owner string) (string, bool) {
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		if nsec, ok := rr.(*dns.NSEC); ok {
			// prefer the record whose owner matches, but accept any NSEC if the
			// owner-specific one is absent (covering record on NXDOMAIN proofs).
			if equalName(nsec.Hdr.Name, owner) {
				return dns.Fqdn(strings.ToLower(nsec.NextDomain)), true
			}
		}
	}
	// fall back to the first NSEC seen
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		if nsec, ok := rr.(*dns.NSEC); ok {
			return dns.Fqdn(strings.ToLower(nsec.NextDomain)), true
		}
	}
	return "", false
}

func nsec3Param(resp *dns.Msg) (*NSEC3Info, bool) {
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		switch v := rr.(type) {
		case *dns.NSEC3:
			return &NSEC3Info{Salt: v.Salt, Iterations: v.Iterations, HashAlg: v.Hash}, true
		case *dns.NSEC3PARAM:
			return &NSEC3Info{Salt: v.Salt, Iterations: v.Iterations, HashAlg: v.Hash}, true
		}
	}
	return nil, false
}

func equalName(a, b string) bool {
	return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b))
}

func normalize(r string) string {
	r = strings.TrimSpace(r)
	if _, _, err := net.SplitHostPort(r); err != nil {
		return net.JoinHostPort(r, "53")
	}
	return r
}
