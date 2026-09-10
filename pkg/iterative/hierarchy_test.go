package iterative

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/miekg/dns"
)

// memHierarchy is an in-memory authoritative DNS tree used to test and
// benchmark the iterative resolver without any real sockets or internet
// traffic. Each "server" is addressed by a synthetic loopback IP; the resolver
// reaches it through the injected exchanger, which routes by destination IP and
// role-plays the appropriate authoritative behaviour (referral / answer /
// NODATA / NXDOMAIN).
type memHierarchy struct {
	servers map[string]*memServer // keyed by IP string
	queries atomic.Int64          // total queries served (for cache-win assertions)
}

type memNS struct {
	name string
	ip   string // "" == glueless
}

type memServer struct {
	ip          string
	authZones   []string
	delegations map[string][]memNS // childZone -> nameservers
	records     map[string]map[uint16][]string
}

func newHierarchy() *memHierarchy { return &memHierarchy{servers: map[string]*memServer{}} }

func (h *memHierarchy) server(ip string) *memServer {
	s, ok := h.servers[ip]
	if !ok {
		s = &memServer{ip: ip, delegations: map[string][]memNS{}, records: map[string]map[uint16][]string{}}
		h.servers[ip] = s
	}
	return s
}

func (s *memServer) authoritative(zones ...string) *memServer {
	for _, z := range zones {
		s.authZones = append(s.authZones, canonical(z))
	}
	return s
}

func (s *memServer) delegate(child string, ns ...memNS) *memServer {
	s.delegations[canonical(child)] = append(s.delegations[canonical(child)], ns...)
	return s
}

func (s *memServer) rr(name string, qtype uint16, data ...string) *memServer {
	name = canonical(name)
	if s.records[name] == nil {
		s.records[name] = map[uint16][]string{}
	}
	s.records[name][qtype] = append(s.records[name][qtype], data...)
	return s
}

func (s *memServer) a(name string, ips ...string) *memServer { return s.rr(name, dns.TypeA, ips...) }
func (s *memServer) cname(name, target string) *memServer    { return s.rr(name, dns.TypeCNAME, target) }

func (s *memServer) hasAny(name string) bool {
	_, ok := s.records[canonical(name)]
	return ok
}

// exchange implements the exchanger interface for the resolver.
func (h *memHierarchy) exchange(ctx context.Context, server netip.AddrPort, msg *dns.Msg) (*dns.Msg, error) {
	h.queries.Add(1)
	srv := h.servers[server.Addr().Unmap().String()]
	m := new(dns.Msg)
	m.SetReply(msg)
	m.RecursionAvailable = false
	if srv == nil {
		return nil, errTimeout // unreachable server (no response)
	}
	q := msg.Question[0]
	qname := canonical(q.Name)
	qtype := q.Qtype

	// most specific authoritative zone for the name
	authZone := ""
	for _, z := range srv.authZones {
		if inBailiwick(qname, z) && len(z) > len(authZone) {
			authZone = z
		}
	}
	// most specific delegation that is an ancestor of the name
	bestChild := ""
	for child := range srv.delegations {
		if inBailiwick(qname, child) && len(child) > len(bestChild) {
			bestChild = child
		}
	}

	// referral: a delegation more specific than what we serve authoritatively
	if bestChild != "" && len(bestChild) > len(authZone) {
		for _, ns := range srv.delegations[bestChild] {
			m.Ns = append(m.Ns, mustRR(fmt.Sprintf("%s 3600 IN NS %s", bestChild, ns.name)))
			if ns.ip != "" {
				m.Extra = append(m.Extra, mustRR(fmt.Sprintf("%s 3600 IN A %s", ns.name, ns.ip)))
			}
		}
		return m, nil
	}

	if authZone == "" {
		m.Rcode = dns.RcodeServerFailure
		return m, nil
	}
	m.Authoritative = true

	if recs := srv.records[qname][qtype]; len(recs) > 0 {
		for _, d := range recs {
			m.Answer = append(m.Answer, mustRR(rrString(qname, qtype, d)))
		}
		return m, nil
	}
	// CNAME indirection
	if cns := srv.records[qname][dns.TypeCNAME]; len(cns) > 0 && qtype != dns.TypeCNAME {
		tgt := canonical(cns[0])
		m.Answer = append(m.Answer, mustRR(fmt.Sprintf("%s 3600 IN CNAME %s", qname, tgt)))
		// include in-zone target records (as a real authoritative server would)
		if inBailiwick(tgt, authZone) {
			for _, d := range srv.records[tgt][qtype] {
				m.Answer = append(m.Answer, mustRR(rrString(tgt, qtype, d)))
			}
		}
		return m, nil
	}

	// NODATA (name exists, type doesn't) vs NXDOMAIN
	if !srv.hasAny(qname) {
		m.Rcode = dns.RcodeNameError
	}
	m.Ns = append(m.Ns, mustRR(fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 3600 600 86400 60", authZone, authZone, authZone)))
	return m, nil
}

func (h *memHierarchy) close() {}

// factory returns a newExchanger function that hands every worker the shared
// in-memory hierarchy (no per-worker socket).
func (h *memHierarchy) factory() func() (exchanger, error) {
	return func() (exchanger, error) { return h, nil }
}

func rrString(name string, qtype uint16, data string) string {
	switch qtype {
	case dns.TypeA:
		return fmt.Sprintf("%s 60 IN A %s", name, data)
	case dns.TypeAAAA:
		return fmt.Sprintf("%s 60 IN AAAA %s", name, data)
	case dns.TypeTXT:
		return fmt.Sprintf("%s 60 IN TXT \"%s\"", name, data)
	case dns.TypeNS:
		return fmt.Sprintf("%s 60 IN NS %s", name, data)
	case dns.TypeMX:
		return fmt.Sprintf("%s 60 IN MX 10 %s", name, data)
	default:
		return fmt.Sprintf("%s 60 IN A %s", name, data)
	}
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

// ip4 generates distinct synthetic loopback IPs for hierarchy servers.
func ip4(n int) string { return net.IPv4(127, 0, byte(n>>8), byte(n)).String() }
