package axfr

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// startTCPServer starts a TCP DNS server (AXFR runs over TCP) and returns its addr.
func startTCPServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{Listener: l, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return l.Addr().String(), func() { _ = srv.Shutdown() }
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func TestAttemptAXFR(t *testing.T) {
	zone := "example.com."
	records := func() []dns.RR {
		return []dns.RR{
			mustRR(t, "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 600 86400 60"),
			mustRR(t, "example.com. 3600 IN NS ns1.example.com."),
			mustRR(t, "www.example.com. 3600 IN A 93.184.216.34"),
			mustRR(t, "mail.example.com. 3600 IN A 93.184.216.35"),
			mustRR(t, "ftp.example.com. 3600 IN CNAME www.example.com."),
			mustRR(t, "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 600 86400 60"),
		}
	}

	addr, stop := startTCPServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Qtype == dns.TypeAXFR {
			ch := make(chan *dns.Envelope)
			tr := new(dns.Transfer)
			go func() {
				ch <- &dns.Envelope{RR: records()}
				close(ch)
			}()
			_ = tr.Out(w, r, ch)
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
	})
	defer stop()

	var streamed []string
	res, err := Attempt(context.Background(), Config{
		Zone:        zone,
		Nameservers: []string{addr},
		OnName:      func(n string) { streamed = append(streamed, n) },
	})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	want := map[string]bool{"www.example.com": false, "mail.example.com": false, "ftp.example.com": false, "example.com": false}
	for _, n := range res.Names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("expected %q in transferred names %v", n, res.Names)
		}
	}
	if len(streamed) != len(res.Names) {
		t.Errorf("OnName fired %d times, result has %d names", len(streamed), len(res.Names))
	}
}

func TestAttemptRefused(t *testing.T) {
	// a server that refuses transfers must yield an error, not a panic/partial.
	addr, stop := startTCPServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
	})
	defer stop()

	_, err := Attempt(context.Background(), Config{Zone: "secure.example.", Nameservers: []string{addr}})
	if err == nil {
		t.Fatal("expected error when transfer is refused")
	}
}
