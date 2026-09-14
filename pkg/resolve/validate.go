package resolve

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ValidateConfig configures resolver-list curation. It is the native, embeddable
// equivalent of dnsvalidator: it weeds out resolvers that are dead, that lie by
// hijacking NXDOMAIN (returning an address for names that do not exist), or that
// cannot resolve a known-good name. Output quality for any mass-resolution run is
// bounded by resolver-list quality, so this is the most important accuracy knob.
type ValidateConfig struct {
	// Resolvers is the candidate list (host or host:port; :53 assumed).
	Resolvers []string
	// GoodDomains are names expected to resolve to at least one A record. A
	// resolver must successfully resolve one of them to pass. If empty, a small
	// built-in set of stable, non-wildcard domains is used.
	GoodDomains []string
	// Timeout is the per-query timeout. Default 3s.
	Timeout time.Duration
	// Concurrency caps simultaneous resolver checks. Default 50.
	Concurrency int
	// MaxRTT optionally rejects resolvers slower than this on the positive
	// probe. 0 disables the latency filter.
	MaxRTT time.Duration
	// OnResolver is an optional progress callback fired once per checked
	// resolver (safe for concurrent use).
	OnResolver func(ResolverCheck)
}

// ResolverCheck is the verdict for a single candidate resolver.
type ResolverCheck struct {
	Resolver string        // normalized host:port
	OK       bool          // passed all checks
	Reason   string        // failure reason when !OK
	RTT      time.Duration // latency of the positive probe (when measured)
}

// defaultGoodDomains are widely-deployed names that resolve to A records and are
// not wildcard zones, suitable as positive/negative resolver probes.
var defaultGoodDomains = []string{"google.com", "cloudflare.com", "wikipedia.org"}

// ValidateResolvers checks each candidate resolver and returns the subset that
// passed plus the full per-resolver report. It performs a handful of low-volume
// queries per resolver (not a mass run), so it uses a simple bounded worker pool.
func ValidateResolvers(ctx context.Context, cfg ValidateConfig) (good []string, report []ResolverCheck, err error) {
	if len(cfg.Resolvers) == 0 {
		return nil, nil, fmt.Errorf("no resolvers to validate")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	goodDomains := cfg.GoodDomains
	if len(goodDomains) == 0 {
		goodDomains = defaultGoodDomains
	}

	report = make([]ResolverCheck, len(cfg.Resolvers))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for i, r := range cfg.Resolvers {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int, r string) {
			defer wg.Done()
			defer func() { <-sem }()
			chk := checkResolver(ctx, normalizeResolver(r), goodDomains, cfg.Timeout, cfg.MaxRTT)
			report[i] = chk
			if cfg.OnResolver != nil {
				cfg.OnResolver(chk)
			}
		}(i, r)
	}
	wg.Wait()

	for _, chk := range report {
		if chk.OK {
			good = append(good, chk.Resolver)
		}
	}
	return good, report, nil
}

// checkResolver runs the liveness, NXDOMAIN-hijack and positive-resolution
// probes against a single resolver.
func checkResolver(ctx context.Context, server string, goodDomains []string, timeout, maxRTT time.Duration) ResolverCheck {
	chk := ResolverCheck{Resolver: server}
	client := &dns.Client{Timeout: timeout}

	// 1) NXDOMAIN-hijack probe: a random label under a good domain must NOT
	// resolve to an address. A resolver that answers with an A is lying.
	probe := randomLabel() + "." + goodDomains[0]
	if resp, _, err := exchangeA(ctx, client, server, probe); err == nil && resp != nil {
		if hasAddress(resp) {
			chk.Reason = "hijacks NXDOMAIN (answers for nonexistent name)"
			return chk
		}
	}
	// (a transport error here is tolerated; the positive probe is the liveness
	// gate, since some resolvers drop obviously bogus queries.)

	// 2) positive probe: at least one good domain must resolve to an A.
	resolvedAny := false
	for _, d := range goodDomains {
		start := time.Now()
		resp, _, err := exchangeA(ctx, client, server, d)
		if err != nil || resp == nil {
			continue
		}
		if resp.Rcode == dns.RcodeSuccess && hasAddress(resp) {
			chk.RTT = time.Since(start)
			resolvedAny = true
			break
		}
	}
	if !resolvedAny {
		chk.Reason = "could not resolve any known-good domain"
		return chk
	}
	if maxRTT > 0 && chk.RTT > maxRTT {
		chk.Reason = fmt.Sprintf("too slow (%s > %s)", chk.RTT.Round(time.Millisecond), maxRTT)
		return chk
	}

	chk.OK = true
	return chk
}

func exchangeA(ctx context.Context, client *dns.Client, server, name string) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	return client.ExchangeContext(ctx, m, server)
}

func hasAddress(m *dns.Msg) bool {
	for _, rr := range m.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			return true
		}
	}
	return false
}

func randomLabel() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(b)
}
