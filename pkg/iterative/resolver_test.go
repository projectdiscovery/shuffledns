package iterative

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// buildTestHierarchy wires a small but representative tree:
//
//	root(127.0.0.1) -> com.(127.0.2.0), net.(127.0.3.0)
//	com.            -> example.com.(127.0.4.0, glued)
//	                -> glueless.com. (NS ns.ext.net., NO glue)
//	net.            -> ext.net.(127.0.5.0, glued)
//	example.com.    : www A, many hostN A, alias CNAME->www, (NODATA/NXDOMAIN otherwise)
//	ext.net.        : ns.ext.net. A (so glueless delegation resolves), svc A
func buildTestHierarchy() *memHierarchy {
	h := newHierarchy()
	const (
		rootIP = "127.0.0.1"
		comIP  = "127.0.2.0"
		netIP  = "127.0.3.0"
		exIP   = "127.0.4.0"
		extIP  = "127.0.5.0"
	)
	h.server(rootIP).authoritative(".").
		delegate("com.", memNS{name: "a.gtld.net.", ip: comIP}).
		delegate("net.", memNS{name: "a.gtld-net.net.", ip: netIP})

	h.server(comIP).authoritative("com.").
		delegate("example.com.", memNS{name: "ns.example.com.", ip: exIP}).
		delegate("glueless.com.", memNS{name: "ns.ext.net."}) // glueless: no IP

	h.server(netIP).authoritative("net.").
		delegate("ext.net.", memNS{name: "ns.ext.net.", ip: extIP})

	ex := h.server(exIP).authoritative("example.com.")
	ex.a("www.example.com.", "93.184.216.34")
	ex.cname("alias.example.com.", "www.example.com.")
	for i := 0; i < 50; i++ {
		ex.a(fmt.Sprintf("host%d.example.com.", i), fmt.Sprintf("198.51.100.%d", i+1))
	}

	extn := h.server(extIP).authoritative("ext.net.", "glueless.com.")
	extn.a("ns.ext.net.", extIP)
	extn.a("svc.glueless.com.", "203.0.113.7")
	return h
}

func newTestResolver(t *testing.T, h *memHierarchy, hooks Hooks) *Resolver {
	t.Helper()
	r, err := New(Options{
		RootServers: []string{"127.0.0.1"},
		QueryType:   dns.TypeA,
		Concurrency: 8,
		Hooks:       hooks,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.newExchanger = h.factory()
	return r
}

func TestIterativeBasicResolution(t *testing.T) {
	h := buildTestHierarchy()
	r := newTestResolver(t, h, Hooks{})

	res, err := r.Resolve(context.Background(), "www.example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.A) != 1 || res.A[0] != "93.184.216.34" {
		t.Fatalf("unexpected A records: %#v", res.A)
	}
	if res.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", res.Rcode)
	}
}

func TestIterativeCNAME(t *testing.T) {
	h := buildTestHierarchy()
	r := newTestResolver(t, h, Hooks{})

	res, err := r.Resolve(context.Background(), "alias.example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.A) != 1 || res.A[0] != "93.184.216.34" {
		t.Fatalf("CNAME target A not resolved: %#v", res.A)
	}
	if len(res.CNAME) == 0 || res.CNAME[0] != "www.example.com" {
		t.Fatalf("expected CNAME chain to www.example.com, got %#v", res.CNAME)
	}
}

func TestIterativeNXDOMAIN(t *testing.T) {
	h := buildTestHierarchy()
	r := newTestResolver(t, h, Hooks{})

	res, err := r.Resolve(context.Background(), "nope.example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", res.Rcode)
	}
	if len(res.A) != 0 {
		t.Fatalf("NXDOMAIN should have no A records: %#v", res.A)
	}
}

func TestIterativeGluelessDelegation(t *testing.T) {
	h := buildTestHierarchy()
	r := newTestResolver(t, h, Hooks{})

	// svc.glueless.com is served by ns.ext.net., which has NO glue at com.;
	// the resolver must resolve the nameserver's address first.
	res, err := r.Resolve(context.Background(), "svc.glueless.com", dns.TypeA)
	if err != nil {
		t.Fatalf("glueless resolution failed: %v", err)
	}
	if len(res.A) != 1 || res.A[0] != "203.0.113.7" {
		t.Fatalf("unexpected A for glueless: %#v", res.A)
	}
}

func TestIterativeCacheReuseReducesQueries(t *testing.T) {
	h := buildTestHierarchy()
	r := newTestResolver(t, h, Hooks{})
	ctx := context.Background()

	// cold: root -> com -> example.com -> answer
	if _, err := r.Resolve(ctx, "host0.example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	cold := h.queries.Load()

	// warm: example.com delegation cached, expect a single authoritative query
	before := h.queries.Load()
	if _, err := r.Resolve(ctx, "host1.example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	warm := h.queries.Load() - before

	if cold < 3 {
		t.Fatalf("expected cold path to take >=3 queries (root,tld,auth), got %d", cold)
	}
	if warm != 1 {
		t.Fatalf("expected warm path to take exactly 1 query (cached delegation), got %d", warm)
	}
}

func TestIterativeStreamConcurrent(t *testing.T) {
	h := buildTestHierarchy()
	r := newTestResolver(t, h, Hooks{})

	names := make(chan string)
	go func() {
		defer close(names)
		for i := 0; i < 50; i++ {
			names <- fmt.Sprintf("host%d.example.com", i)
		}
	}()

	var mu sync.Mutex
	got := map[string]string{}
	err := r.ResolveStream(context.Background(), names, StreamConfig{
		OnResult: func(res *resolve.Result) {
			mu.Lock()
			if len(res.A) > 0 {
				got[res.Name] = res.A[0]
			}
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 50 {
		t.Fatalf("expected 50 resolved names, got %d", len(got))
	}
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("host%d.example.com", i)
		want := fmt.Sprintf("198.51.100.%d", i+1)
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
}
