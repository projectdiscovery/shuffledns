package resolve

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startDNSServer starts a UDP DNS server on loopback with the given handler and
// returns its address and a stop function.
func startDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestValidateResolvers(t *testing.T) {
	// good resolver: resolves good.test, NXDOMAIN for anything else.
	goodAddr, stopGood := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "good.test." && q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR("good.test. 60 IN A 1.2.3.4")
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	defer stopGood()

	// hijacking resolver: answers an A for every name (lies about NXDOMAIN).
	hijackAddr, stopHijack := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 6.6.6.6")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	defer stopHijack()

	// dead resolver: nothing listening on this port.
	deadAddr := "127.0.0.1:1"

	good, report, err := ValidateResolvers(context.Background(), ValidateConfig{
		Resolvers:   []string{goodAddr, hijackAddr, deadAddr},
		GoodDomains: []string{"good.test"},
		Timeout:     2 * time.Second,
		Concurrency: 5,
	})
	if err != nil {
		t.Fatalf("ValidateResolvers: %v", err)
	}
	if len(report) != 3 {
		t.Fatalf("expected 3 reports, got %d", len(report))
	}
	if len(good) != 1 || good[0] != goodAddr {
		t.Fatalf("expected only the good resolver to pass, got %v", good)
	}

	// verify reasons for the rejected ones
	byAddr := map[string]ResolverCheck{}
	for _, c := range report {
		byAddr[c.Resolver] = c
	}
	if c := byAddr[hijackAddr]; c.OK || c.Reason == "" {
		t.Fatalf("hijacking resolver should be rejected with a reason, got %+v", c)
	}
	if c := byAddr[deadAddr]; c.OK {
		t.Fatalf("dead resolver should be rejected")
	}
}

func TestValidateResolversEmpty(t *testing.T) {
	if _, _, err := ValidateResolvers(context.Background(), ValidateConfig{}); err == nil {
		t.Fatal("expected error for empty resolver list")
	}
}
