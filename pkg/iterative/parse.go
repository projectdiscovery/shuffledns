package iterative

import (
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// chaseCNAME follows a CNAME chain present in answer starting at start and
// returns the final target name plus the chain of CNAME targets traversed. If
// there is no CNAME for start, it returns (start, nil).
func chaseCNAME(answer []dns.RR, start string) (string, []string) {
	cur := canonical(start)
	var chain []string
	seen := map[string]struct{}{cur: {}}
	for {
		var next string
		for _, rr := range answer {
			c, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			if canonical(c.Header().Name) == cur {
				next = canonical(c.Target)
				break
			}
		}
		if next == "" {
			return cur, chain
		}
		if _, dup := seen[next]; dup {
			return cur, chain
		}
		seen[next] = struct{}{}
		chain = append(chain, strings.TrimSuffix(next, "."))
		cur = next
	}
}

// answersType reports whether answer contains at least one record of qtype
// owned by name.
func answersType(answer []dns.RR, name string, qtype uint16) bool {
	name = canonical(name)
	for _, rr := range answer {
		if rr.Header().Rrtype == qtype && canonical(rr.Header().Name) == name {
			return true
		}
	}
	return false
}

// buildResult converts a final authoritative response into a resolve.Result,
// collecting every record type so the output formatter can render faithfully.
// cnameChain holds CNAME targets traversed before the final answer.
func buildResult(name string, qtype uint16, resp *dns.Msg, server string, cnameChain []string) *resolve.Result {
	r := &resolve.Result{
		Name:      strings.TrimSuffix(canonical(name), "."),
		Type:      qtype,
		Rcode:     resp.Rcode,
		Resolver:  server,
		Msg:       resp,
		Timestamp: time.Now(),
		CNAME:     append([]string{}, cnameChain...),
	}
	// Only harvest records owned by the queried name or a name reached through
	// its CNAME chain. Without this an in-bailiwick-but-hostile (or lame)
	// authoritative could staple unrelated A/AAAA records for other owners into
	// this name's result.
	validOwners := map[string]struct{}{canonical(name): {}}
	for _, c := range cnameChain {
		validOwners[canonical(c)] = struct{}{}
	}
	for changed := true; changed; {
		changed = false
		for _, rr := range resp.Answer {
			c, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			if _, in := validOwners[canonical(c.Header().Name)]; !in {
				continue
			}
			if tgt := canonical(c.Target); !mapHas(validOwners, tgt) {
				validOwners[tgt] = struct{}{}
				changed = true
			}
		}
	}
	for _, rr := range resp.Answer {
		if _, ok := validOwners[canonical(rr.Header().Name)]; !ok {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			r.A = append(r.A, v.A.String())
		case *dns.AAAA:
			r.AAAA = append(r.AAAA, v.AAAA.String())
		case *dns.CNAME:
			tgt := strings.TrimSuffix(canonical(v.Target), ".")
			if !contains(r.CNAME, tgt) {
				r.CNAME = append(r.CNAME, tgt)
			}
		case *dns.NS:
			r.NS = append(r.NS, strings.TrimSuffix(canonical(v.Ns), "."))
		case *dns.PTR:
			r.PTR = append(r.PTR, strings.TrimSuffix(canonical(v.Ptr), "."))
		case *dns.MX:
			r.MX = append(r.MX, strings.TrimSuffix(canonical(v.Mx), "."))
		case *dns.TXT:
			r.TXT = append(r.TXT, strings.Join(v.Txt, ""))
		case *dns.SOA:
			r.SOA = append(r.SOA, strings.TrimSuffix(canonical(v.Ns), "."))
		}
	}
	if len(r.CNAME) == 0 {
		r.CNAME = nil
	}
	return r
}

// mergeCNAME stitches a CNAME-followed sub-resolution back onto the original
// query name, preserving the original name/type but carrying the final answer's
// records and the full CNAME chain.
func mergeCNAME(name string, qtype uint16, chain []string, server string, sub *resolve.Result) *resolve.Result {
	out := &resolve.Result{
		Name:      strings.TrimSuffix(canonical(name), "."),
		Type:      qtype,
		Rcode:     sub.Rcode,
		Resolver:  server,
		Msg:       sub.Msg,
		Timestamp: sub.Timestamp,
		A:         sub.A,
		AAAA:      sub.AAAA,
		PTR:       sub.PTR,
		MX:        sub.MX,
		TXT:       sub.TXT,
		NS:        sub.NS,
		SOA:       sub.SOA,
	}
	cn := append([]string{}, chain...)
	cn = append(cn, sub.CNAME...)
	if len(cn) > 0 {
		out.CNAME = cn
	}
	if out.Resolver == "" {
		out.Resolver = sub.Resolver
	}
	return out
}

func mapHas(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
