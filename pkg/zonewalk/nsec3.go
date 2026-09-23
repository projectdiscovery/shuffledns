package zonewalk

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// maxNSEC3Iterations caps the SHA-1 iteration count we are willing to process.
// dns.HashName runs iter extra SHA-1 rounds per hash and the target controls
// iter (up to 65535); crack does len(candidates)*len(harvested) hashes, so a
// hostile zone advertising a huge count could burn billions of SHA-1 ops.
// RFC 9276 treats anything above a small number as unreasonable.
const maxNSEC3Iterations = 500

// CrackConfig controls an NSEC3 harvest-and-crack.
type CrackConfig struct {
	// Zone is the NSEC3-signed apex to enumerate (e.g. "example.com").
	Zone string
	// Resolvers are DNSSEC-aware resolvers (host or host:port); the first is used.
	Resolvers []string
	// Timeout is the per-query timeout. Default 5s.
	Timeout time.Duration
	// MaxQueries bounds the harvest phase (number of probe queries). Default 2000.
	MaxQueries int
	// Candidates is the wordlist of labels to crack against the harvested hash
	// ring (e.g. "www", "mail"); each is hashed and matched offline.
	Candidates []string
	// OnName fires for each recovered (cracked) name.
	OnName func(string)
}

// CrackResult is the outcome of an NSEC3 harvest-and-crack.
type CrackResult struct {
	Zone            string
	Salt            string
	Iterations      uint16
	HashAlg         uint8
	HarvestedHashes int      // distinct NSEC3 records collected (existing-name hashes)
	Names           []string // recovered existing names (no trailing dot)
	Saturated       bool     // harvest reached saturation (ring likely complete)
}

// CrackNSEC3 enumerates an NSEC3-signed zone offline-style: it first harvests
// the zone's NSEC3 records by probing for non-existent names (each NXDOMAIN
// proof leaks NSEC3 records that cover existing-name hashes), walking until the
// hash ring saturates, then cracks the supplied wordlist by matching each
// candidate's hash against the harvested records. Only true positives are
// reported. Completeness depends on harvest coverage and the wordlist; this is
// the standard nsec3walker approach.
func CrackNSEC3(ctx context.Context, cfg CrackConfig) (*CrackResult, error) {
	if strings.TrimSpace(cfg.Zone) == "" {
		return nil, fmt.Errorf("zone is required")
	}
	if len(cfg.Resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxQueries <= 0 {
		cfg.MaxQueries = 2000
	}
	server := normalize(cfg.Resolvers[0])
	apex := dns.Fqdn(strings.ToLower(cfg.Zone))
	client := &dns.Client{Timeout: cfg.Timeout}

	res := &CrackResult{Zone: cfg.Zone}

	// harvested NSEC3 records, deduplicated by owner name.
	harvested := map[string]*dns.NSEC3{}
	collect := func(resp *dns.Msg) int {
		added := 0
		for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
			n3, ok := rr.(*dns.NSEC3)
			if !ok {
				continue
			}
			key := strings.ToLower(n3.Hdr.Name)
			if _, dup := harvested[key]; !dup {
				harvested[key] = n3
				added++
				if res.Salt == "" && res.Iterations == 0 {
					res.Salt, res.Iterations, res.HashAlg = n3.Salt, n3.Iterations, n3.Hash
				}
			}
		}
		return added
	}

	covered := func(name string) bool {
		for _, n3 := range harvested {
			if n3.Cover(name) || n3.Match(name) {
				return true
			}
		}
		return false
	}

	// harvest: probe random non-existent names; each proof extends ring coverage.
	const saturation = 64 // consecutive already-covered probes => ring ~complete
	miss := 0
	for q := 0; q < cfg.MaxQueries; q++ {
		if err := ctx.Err(); err != nil {
			break
		}
		probe := randomLabel() + "." + apex
		if len(harvested) > 0 && covered(probe) {
			miss++
			if miss >= saturation {
				res.Saturated = true
				break
			}
			continue
		}
		miss = 0
		resp, err := queryDO(ctx, client, server, probe, dns.TypeA)
		if err != nil {
			continue
		}
		collect(resp)
		// Bail before any expensive Cover/Match on the next iteration if the zone
		// advertises an abusive iteration count.
		if res.Iterations > maxNSEC3Iterations {
			res.HarvestedHashes = len(harvested)
			return res, fmt.Errorf("nsec3 iterations %d exceed cap %d; refusing to crack (DoS risk)", res.Iterations, maxNSEC3Iterations)
		}
	}
	res.HarvestedHashes = len(harvested)

	// crack: match each candidate's hash against the harvested ring.
	seen := map[string]struct{}{}
	for _, label := range cfg.Candidates {
		label = strings.TrimSpace(strings.ToLower(label))
		if label == "" {
			continue
		}
		name := label + "." + apex
		for _, n3 := range harvested {
			if n3.Match(name) {
				owner := strings.TrimSuffix(name, ".")
				if _, dup := seen[owner]; !dup {
					seen[owner] = struct{}{}
					res.Names = append(res.Names, owner)
					if cfg.OnName != nil {
						cfg.OnName(owner)
					}
				}
				break
			}
		}
	}
	return res, nil
}

func queryDO(ctx context.Context, client *dns.Client, server, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO bit
	resp, _, err := client.ExchangeContext(ctx, m, server)
	return resp, err
}

const labelAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomLabel() string {
	n := 10 + rand.IntN(6)
	b := make([]byte, n)
	for i := range b {
		b[i] = labelAlphabet[rand.IntN(len(labelAlphabet))]
	}
	return string(b)
}
