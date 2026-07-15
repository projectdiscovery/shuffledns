// Package axfr attempts DNS zone transfers (AXFR, with IXFR fallback) against a
// zone's authoritative nameservers. A misconfigured nameserver that allows
// transfers from arbitrary clients returns the entire zone — every owner name —
// in a single exchange, which is the highest-payoff subdomain enumeration
// shortcut: no wordlist, no guessing, complete and authoritative.
//
// Open AXFR is uncommon on well-run zones (low single-digit percent), but it is
// nearly free to attempt and total when it lands, so it belongs as a first pass
// before bruteforce. Secondary/forgotten nameservers are frequently laxer than
// the primary, so every nameserver of the zone is tried.
package axfr

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Config controls a zone-transfer attempt.
type Config struct {
	// Zone is the apex to transfer (e.g. "example.com").
	Zone string
	// Resolvers are used to discover the zone's NS set and resolve nameserver
	// addresses when Nameservers is not supplied (host or host:port).
	Resolvers []string
	// Nameservers optionally lists explicit nameserver addresses to try
	// (host or host:port); when set, NS discovery is skipped.
	Nameservers []string
	// Timeout is the per-nameserver transfer timeout. Default 10s.
	Timeout time.Duration
	// OnName fires for each newly discovered owner name (deduplicated).
	OnName func(string)
	// OnNameserver fires after each nameserver attempt with its outcome.
	OnNameserver func(ns string, names int, err error)
}

// Result is the outcome of a successful zone transfer.
type Result struct {
	Zone       string
	Nameserver string   // nameserver that allowed the transfer
	Names      []string // unique owner names within the zone (no trailing dot)
	Records    int      // total resource records transferred
}

// Attempt tries to transfer the zone from each of its nameservers and returns
// the first successful transfer. It returns an error only when no nameserver
// allowed the transfer (the common case for well-configured zones).
func Attempt(ctx context.Context, cfg Config) (*Result, error) {
	if strings.TrimSpace(cfg.Zone) == "" {
		return nil, fmt.Errorf("zone is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	apex := dns.Fqdn(strings.ToLower(cfg.Zone))

	servers := cfg.Nameservers
	if len(servers) == 0 {
		var err error
		servers, err = discoverNameservers(ctx, apex, cfg.Resolvers, cfg.Timeout)
		if err != nil {
			return nil, err
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no nameservers found for %s", cfg.Zone)
	}

	var lastErr error
	for _, ns := range servers {
		res, err := transferFrom(ctx, apex, withPort(ns), cfg)
		if cfg.OnNameserver != nil {
			n := 0
			if res != nil {
				n = len(res.Names)
			}
			cfg.OnNameserver(ns, n, err)
		}
		if err == nil && res != nil && len(res.Names) > 0 {
			res.Zone = cfg.Zone
			return res, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no nameserver allowed transfer of %s", cfg.Zone)
	}
	return nil, lastErr
}

// transferFrom performs the AXFR (falling back to IXFR) against one nameserver.
func transferFrom(ctx context.Context, apex, nsAddr string, cfg Config) (*Result, error) {
	run := func(setup func(*dns.Msg)) (*Result, error) {
		t := &dns.Transfer{DialTimeout: cfg.Timeout, ReadTimeout: cfg.Timeout, WriteTimeout: cfg.Timeout}
		m := new(dns.Msg)
		setup(m)
		ch, err := t.In(m, nsAddr)
		if err != nil {
			return nil, err
		}
		res := &Result{Nameserver: nsAddr}
		seen := map[string]struct{}{}
		for env := range ch {
			if env.Error != nil {
				if len(res.Names) > 0 {
					return res, nil // partial transfer is still useful
				}
				return nil, env.Error
			}
			for _, rr := range env.RR {
				res.Records++
				owner := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")
				name := dns.Fqdn(strings.ToLower(rr.Header().Name))
				if !inZone(name, apex) {
					continue
				}
				if _, dup := seen[owner]; dup {
					continue
				}
				seen[owner] = struct{}{}
				res.Names = append(res.Names, owner)
				if cfg.OnName != nil {
					cfg.OnName(owner)
				}
			}
			if err := ctx.Err(); err != nil {
				return res, err
			}
		}
		return res, nil
	}

	res, err := run(func(m *dns.Msg) { m.SetAxfr(apex) })
	if err == nil && res != nil && len(res.Names) > 0 {
		return res, nil
	}
	// some servers refuse AXFR but permit IXFR; try it as a fallback.
	if res2, err2 := run(func(m *dns.Msg) { m.SetIxfr(apex, 0, "", "") }); err2 == nil && res2 != nil && len(res2.Names) > 0 {
		return res2, nil
	}
	return res, err
}

// discoverNameservers resolves the zone's NS set and their addresses.
func discoverNameservers(ctx context.Context, apex string, resolvers []string, timeout time.Duration) ([]string, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("resolvers are required to discover nameservers (or pass Nameservers)")
	}
	server := withPort(resolvers[0])
	client := &dns.Client{Timeout: timeout}

	m := new(dns.Msg)
	m.SetQuestion(apex, dns.TypeNS)
	m.RecursionDesired = true
	resp, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, fmt.Errorf("NS lookup for %s failed: %w", apex, err)
	}

	var nsNames []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}

	var addrs []string
	seen := map[string]struct{}{}
	for _, ns := range nsNames {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			am := new(dns.Msg)
			am.SetQuestion(dns.Fqdn(ns), qt)
			am.RecursionDesired = true
			ar, _, aerr := client.ExchangeContext(ctx, am, server)
			if aerr != nil {
				continue
			}
			for _, rr := range ar.Answer {
				var ip string
				switch v := rr.(type) {
				case *dns.A:
					ip = v.A.String()
				case *dns.AAAA:
					ip = v.AAAA.String()
				}
				if ip == "" {
					continue
				}
				if _, dup := seen[ip]; dup {
					continue
				}
				seen[ip] = struct{}{}
				addrs = append(addrs, ip)
			}
		}
	}
	return addrs, nil
}

func inZone(name, apex string) bool {
	name, apex = dns.Fqdn(strings.ToLower(name)), dns.Fqdn(strings.ToLower(apex))
	return name == apex || strings.HasSuffix(name, "."+apex)
}

func withPort(s string) string {
	s = strings.TrimSpace(s)
	if _, _, err := net.SplitHostPort(s); err != nil {
		return net.JoinHostPort(s, "53")
	}
	return s
}
