package wildcards

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func newConcurrentTestResolver(t *testing.T) *Resolver {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addresses := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	var next atomic.Uint32
	started := make(chan struct{})
	done := make(chan error, 1)
	server := &dns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(req)
			for _, question := range req.Question {
				if question.Qtype != dns.TypeA {
					continue
				}
				address := addresses[(next.Add(1)-1)%uint32(len(addresses))]
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.ParseIP(address),
				})
			}
			if err := w.WriteMsg(response); err != nil {
				t.Errorf("write DNS response: %v", err)
			}
		}),
	}
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("stop DNS server: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("serve DNS: %v", err)
		}
	})

	resolver, err := NewResolver([]string{"example.test"}, 1, []string{conn.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	resolver.SetProbeCount(1)
	return resolver
}

func TestLookupHostReturnsSnapshot(t *testing.T) {
	resolver := newConcurrentTestResolver(t)
	isWildcard, ips := resolver.LookupHost("first.example.test", []string{"10.0.0.1"})
	if !isWildcard || len(ips) != 1 {
		t.Fatalf("initial wildcard result: wildcard=%t, IPs=%v", isWildcard, ips)
	}

	resolver.LookupHost("second.example.test", []string{"203.0.113.1"})
	if len(ips) != 1 {
		t.Fatalf("previous result changed after cache update: %v", ips)
	}
}

func TestConcurrentWildcardCacheReads(t *testing.T) {
	resolver := newConcurrentTestResolver(t)
	_, ips := resolver.LookupHost("first.example.test", []string{"10.0.0.1"})
	if len(ips) == 0 {
		t.Fatal("expected cached wildcard IP")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 1000 {
				for range ips {
				}
				resolver.GetAllWildcardIPs()
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 50 {
				resolver.LookupHost("second.example.test", []string{"203.0.113.1"})
			}
		}()
	}
	close(start)
	wg.Wait()
}
