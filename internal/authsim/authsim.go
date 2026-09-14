// Package authsim provides a real-socket, loopback authoritative DNS hierarchy
// (root -> TLD -> per-domain authoritative servers) for benchmarking the
// iterative-from-root resolver entirely offline. Every server binds a distinct
// 127.0.0.x address (Linux routes all of 127/8 to loopback without aliasing),
// so the iterative resolver follows real referrals and glue over real UDP
// without a single packet leaving the host.
//
// Answers use simdns.SyntheticIP, identical to the simulated recursive-resolver
// battery, so the iterative engine (talking to these authoritative servers) and
// the stub engine (talking to recursors) resolve the exact same workload and
// their results can be compared for accuracy (false negatives).
package authsim

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/internal/simdns"
)

type nsEntry struct {
	name string
	ip   string // "" == glueless
}

type zoneServer struct {
	ip          string
	port        int
	conn        *net.UDPConn
	authZones   []string
	delegations map[string][]nsEntry
	closeCh     chan struct{}
	wg          sync.WaitGroup
	queries     *atomic.Int64
}

// Hierarchy is a running authoritative tree.
type Hierarchy struct {
	RootAddr string   // "127.0.0.1:port" to seed the iterative resolver's roots
	Names    []string // all resolvable leaf names (host{n}.d{k}.com)
	Port     int
	Queries  atomic.Int64

	servers []*zoneServer
}

// Build starts an authoritative hierarchy with `domains` registrable domains
// under .com, each served by its own authoritative server with `hosts` names.
// All servers listen on `port` across distinct loopback IPs.
func Build(domains, hosts, port int) (*Hierarchy, error) {
	h := &Hierarchy{Port: port}

	const rootIP = "127.0.0.1"
	const comIP = "127.0.0.2"

	root := h.newServer(rootIP, port, ".")
	root.delegations["com."] = []nsEntry{{name: "a.gtld-servers.net.", ip: comIP}}

	com := h.newServer(comIP, port, "com.")

	for d := 0; d < domains; d++ {
		zone := fmt.Sprintf("d%d.com.", d)
		authIP := domainIP(d)
		nsName := fmt.Sprintf("ns.%s", zone)
		com.delegations[zone] = []nsEntry{{name: nsName, ip: authIP}}
		h.newServer(authIP, port, zone)
		for n := 0; n < hosts; n++ {
			h.Names = append(h.Names, fmt.Sprintf("host%d.d%d.com", n, d))
		}
	}

	for _, s := range h.servers {
		if err := s.start(); err != nil {
			h.Stop()
			return nil, fmt.Errorf("bind %s:%d: %w (on macOS only 127.0.0.1 is available; run in Docker/Linux)", s.ip, port, err)
		}
	}
	h.RootAddr = net.JoinHostPort(rootIP, fmt.Sprint(port))
	return h, nil
}

func (h *Hierarchy) newServer(ip string, port int, zones ...string) *zoneServer {
	s := &zoneServer{
		ip:          ip,
		port:        port,
		authZones:   zones,
		delegations: map[string][]nsEntry{},
		closeCh:     make(chan struct{}),
		queries:     &h.Queries,
	}
	h.servers = append(h.servers, s)
	return s
}

// Stop shuts down all servers.
func (h *Hierarchy) Stop() {
	for _, s := range h.servers {
		select {
		case <-s.closeCh:
		default:
			close(s.closeCh)
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
	for _, s := range h.servers {
		s.wg.Wait()
	}
}

func domainIP(d int) string {
	return net.IPv4(127, 1, byte(d>>8), byte(d)).String()
}

func (s *zoneServer) start() error {
	addr := &net.UDPAddr{IP: net.ParseIP(s.ip), Port: s.port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	_ = conn.SetReadBuffer(8 * 1024 * 1024)
	_ = conn.SetWriteBuffer(8 * 1024 * 1024)
	s.conn = conn
	s.wg.Add(1)
	go s.serve()
	return nil
}

func (s *zoneServer) serve() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closeCh:
				return
			default:
				continue
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handle(pkt, from)
	}
}

func (s *zoneServer) handle(pkt []byte, from *net.UDPAddr) {
	s.queries.Add(1)
	req := new(dns.Msg)
	if req.Unpack(pkt) != nil || len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	qname := canonical(q.Name)

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	// most specific authoritative zone and delegation for the name
	authZone := ""
	for _, z := range s.authZones {
		if inBailiwick(qname, z) && len(z) > len(authZone) {
			authZone = z
		}
	}
	bestChild := ""
	for child := range s.delegations {
		if inBailiwick(qname, child) && len(child) > len(bestChild) {
			bestChild = child
		}
	}

	switch {
	case bestChild != "" && len(bestChild) > len(authZone):
		m.Authoritative = false
		for _, ns := range s.delegations[bestChild] {
			m.Ns = append(m.Ns, mustRR(fmt.Sprintf("%s 3600 IN NS %s", bestChild, ns.name)))
			if ns.ip != "" {
				m.Extra = append(m.Extra, mustRR(fmt.Sprintf("%s 3600 IN A %s", ns.name, ns.ip)))
			}
		}
	case authZone == "":
		m.Rcode = dns.RcodeServerFailure
	case q.Qtype == dns.TypeA && isHostName(qname):
		m.Answer = append(m.Answer, mustRR(fmt.Sprintf("%s 60 IN A %s", qname, simdns.SyntheticIP(qname))))
	case q.Qtype == dns.TypeA && isNSName(qname):
		// answer the server's own NS address if asked (glue self-lookup)
		m.Answer = append(m.Answer, mustRR(fmt.Sprintf("%s 60 IN A %s", qname, s.ip)))
	default:
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, mustRR(fmt.Sprintf("%s 3600 IN SOA ns.%s hostmaster.%s 1 3600 600 86400 60", authZone, authZone, authZone)))
	}

	out, err := m.Pack()
	if err != nil {
		return
	}
	_, _ = s.conn.WriteToUDP(out, from)
}

func isHostName(name string) bool { return strings.HasPrefix(name, "host") }
func isNSName(name string) bool   { return strings.HasPrefix(name, "ns.") }

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

func inBailiwick(child, parent string) bool {
	child, parent = canonical(child), canonical(parent)
	if parent == "." {
		return true
	}
	return child == parent || strings.HasSuffix(child, "."+parent)
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}
