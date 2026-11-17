package wildcards

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func Test_generateWildcardPermutations(t *testing.T) {
	var tests = []struct {
		subdomain string
		domain    string
		expected  []string
	}{
		{"test", "example.com", []string{"*.example.com"}},
		{"abc.test", "example.com", []string{"*.example.com", "*.test.example.com"}},
		{"xyz.abc.test", "example.com", []string{"*.example.com", "*.test.example.com", "*.abc.test.example.com"}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s.%s", test.subdomain, test.domain), func(t *testing.T) {
			result := generateWildcardPermutations(test.subdomain, test.domain)
			if len(result) != len(test.expected) {
				t.Fatalf("expected %d permutations, got %d", len(test.expected), len(result))
			}
			for i, r := range result {
				if r != test.expected[i] {
					t.Fatalf("expected %s, got %s", test.expected[i], r)
				}
			}
		})
	}
}

func Test_Resolver_LookupHost(t *testing.T) {
	resolver, err := NewResolver([]string{"google.com"}, 3, []string{
		"8.8.8.8",
	})
	require.NoError(t, err)

	lookupAndResolve := func(subdomain string, r *Resolver) (bool, map[string]struct{}) {
		ips, err := r.client.Lookup(subdomain)
		require.NoError(t, err)
		require.NotEmpty(t, ips)

		return resolver.LookupHost(subdomain, ips)
	}
	t.Run("normal", func(t *testing.T) {
		isWildcard, wildcards := lookupAndResolve("www.google.com", resolver)
		require.False(t, isWildcard)
		require.Empty(t, wildcards)
	})

	t.Run("wildcard-root-domain", func(t *testing.T) {
		isWildcard, wildcards := lookupAndResolve("campaigns.google.com", resolver)
		require.False(t, isWildcard)
		require.Empty(t, wildcards)
	})

	t.Run("wildcard", func(t *testing.T) {
		isWildcard, wildcards := lookupAndResolve(xid.New().String()+".campaigns.google.com", resolver)
		require.True(t, isWildcard)
		require.NotEmpty(t, wildcards)
		fmt.Printf("wildcards: %v\n", wildcards)
	})
}

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
