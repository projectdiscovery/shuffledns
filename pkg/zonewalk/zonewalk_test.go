package zonewalk

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func startServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestWalkNSEC(t *testing.T) {
	// a tiny NSEC-signed zone: apex -> a -> b -> c -> apex (wrap).
	chain := map[string]string{
		"example.com.":   "a.example.com.",
		"a.example.com.": "b.example.com.",
		"b.example.com.": "c.example.com.",
		"c.example.com.": "example.com.",
	}
	addr, stop := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeNSEC {
			if next, ok := chain[strings.ToLower(q.Name)]; ok {
				nsec := &dns.NSEC{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
					NextDomain: next,
					TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC},
				}
				m.Answer = append(m.Answer, nsec)
			} else {
				m.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(m)
	})
	defer stop()

	res, err := Walk(context.Background(), Config{
		Zone:      "example.com",
		Resolvers: []string{addr},
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if res.NSEC3 {
		t.Fatal("did not expect NSEC3")
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(res.Names) != len(want) {
		t.Fatalf("got %v want %v", res.Names, want)
	}
	for i := range want {
		if res.Names[i] != want[i] {
			t.Fatalf("idx %d: got %q want %q", i, res.Names[i], want[i])
		}
	}
}

func TestNSEC3Detection(t *testing.T) {
	// NSEC3PARAM in the authority section must flag the zone as NSEC3-signed.
	m := new(dns.Msg)
	m.Ns = append(m.Ns, &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 60},
		Hash:       1,
		Iterations: 10,
		Salt:       "abcd",
	})
	info, ok := nsec3Param(m)
	if !ok || info == nil {
		t.Fatalf("expected NSEC3 detection")
	}
	if info.Iterations != 10 || info.Salt != "abcd" {
		t.Fatalf("bad NSEC3 params: %+v", info)
	}
}

func TestWalkMaxNames(t *testing.T) {
	chain := map[string]string{
		"z.com.": "a.z.com.", "a.z.com.": "b.z.com.", "b.z.com.": "c.z.com.", "c.z.com.": "z.com.",
	}
	addr, stop := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if next, ok := chain[strings.ToLower(r.Question[0].Name)]; ok {
			m.Answer = append(m.Answer, &dns.NSEC{
				Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
				NextDomain: next, TypeBitMap: []uint16{dns.TypeA},
			})
		}
		_ = w.WriteMsg(m)
	})
	defer stop()

	res, err := Walk(context.Background(), Config{Zone: "z.com", Resolvers: []string{addr}, MaxNames: 2})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Names) != 2 {
		t.Fatalf("expected MaxNames cap of 2, got %d (%v)", len(res.Names), res.Names)
	}
}
