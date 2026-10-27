package iterative

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// TestReferralBailiwickRejection ensures a parent that tries to delegate (or
// glue) a name outside its own zone is ignored, so it cannot redirect the
// resolver to an attacker-controlled server (cache poisoning).
func TestReferralBailiwickRejection(t *testing.T) {
	r, _ := New(Options{RootServers: []string{"127.0.0.1"}})

	resp := new(dns.Msg)
	// querying under com.; a hostile com server tries to delegate evil.org.
	resp.Ns = []dns.RR{
		mustRR("evil.org. 3600 IN NS ns.evil.org."),
		mustRR("example.com. 3600 IN NS ns.example.com."), // legitimate, in-bailiwick
	}
	resp.Extra = []dns.RR{
		mustRR("ns.evil.org. 3600 IN A 6.6.6.6"),      // out-of-bailiwick glue
		mustRR("ns.example.com. 3600 IN A 127.0.4.0"), // in-bailiwick glue
	}

	s := &session{r: r}
	child := s.parseReferral(resp, "com.", "www.example.com.")
	if child == nil {
		t.Fatal("expected a valid in-bailiwick referral")
	}
	if child.zone != "example.com." {
		t.Fatalf("accepted wrong delegation zone %q (out-of-bailiwick leak?)", child.zone)
	}
	for _, ns := range child.ns {
		if ns.name == "ns.evil.org." {
			t.Fatal("accepted out-of-bailiwick nameserver")
		}
		for _, ip := range ns.addrs {
			if ip.String() == "6.6.6.6" {
				t.Fatal("accepted out-of-bailiwick glue")
			}
		}
	}
}

// TestReferralMustBeCloser ensures a referral to the same or a higher zone is
// rejected (prevents infinite referral loops).
func TestReferralMustBeCloser(t *testing.T) {
	r, _ := New(Options{RootServers: []string{"127.0.0.1"}})
	resp := new(dns.Msg)
	resp.Ns = []dns.RR{mustRR("com. 3600 IN NS a.gtld.net.")}
	s := &session{r: r}
	if child := s.parseReferral(resp, "com.", "www.example.com."); child != nil {
		t.Fatalf("referral to same zone com. should be rejected, got %#v", child)
	}
}

func TestCNAMELoopDetected(t *testing.T) {
	h := newHierarchy()
	h.server("127.0.0.1").authoritative(".").delegate("com.", memNS{name: "ns.com.", ip: "127.0.2.0"})
	ex := h.server("127.0.2.0").authoritative("com.", "loop.com.")
	ex.cname("a.loop.com.", "b.loop.com.")
	ex.cname("b.loop.com.", "a.loop.com.")

	r, _ := New(Options{RootServers: []string{"127.0.0.1"}})
	r.newExchanger = h.factory()

	_, err := r.Resolve(context.Background(), "a.loop.com", dns.TypeA)
	if err != ErrCNAMELoop {
		t.Fatalf("expected ErrCNAMELoop, got %v", err)
	}
}
