package zonewalk

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// buildNSEC3Ring builds a synthetic NSEC3 ring for the given existing names
// under apex, using the supplied salt/iterations. Returns the ring records.
func buildNSEC3Ring(t *testing.T, apex, salt string, iter uint16, names []string) []*dns.NSEC3 {
	t.Helper()
	type he struct {
		name, hash string
	}
	var hs []he
	for _, n := range names {
		fq := dns.Fqdn(strings.ToLower(n))
		hs = append(hs, he{fq, dns.HashName(fq, dns.SHA1, iter, salt)})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })

	var ring []*dns.NSEC3
	for i, h := range hs {
		next := hs[(i+1)%len(hs)].hash
		ring = append(ring, &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: h.hash + "." + apex, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 60},
			Hash:       dns.SHA1,
			Flags:      0,
			Iterations: iter,
			SaltLength: uint8(len(salt) / 2),
			Salt:       salt,
			HashLength: 20,
			NextDomain: next,
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
		})
	}
	return ring
}

func TestCrackNSEC3(t *testing.T) {
	apex := "example.com."
	salt := "deadbeef"
	var iter uint16 = 5
	// existing names in the zone (the apex is part of the ring too).
	existing := []string{"example.com.", "www.example.com.", "mail.example.com.", "ftp.example.com."}
	ring := buildNSEC3Ring(t, apex, salt, iter, existing)

	addr, stop := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		// leak the full NSEC3 ring on every NXDOMAIN proof (a permissive but
		// valid model: real servers leak the covering subset per query).
		for _, n3 := range ring {
			m.Ns = append(m.Ns, n3)
		}
		_ = w.WriteMsg(m)
	})
	defer stop()

	var recovered []string
	res, err := CrackNSEC3(context.Background(), CrackConfig{
		Zone:       "example.com",
		Resolvers:  []string{addr},
		MaxQueries: 50,
		Candidates: []string{"www", "mail", "ftp", "doesnotexist", "admin"},
		OnName:     func(n string) { recovered = append(recovered, n) },
	})
	if err != nil {
		t.Fatalf("CrackNSEC3: %v", err)
	}
	if res.HarvestedHashes != len(ring) {
		t.Fatalf("expected %d harvested NSEC3 records, got %d", len(ring), res.HarvestedHashes)
	}
	got := map[string]bool{}
	for _, n := range res.Names {
		got[n] = true
	}
	for _, want := range []string{"www.example.com", "mail.example.com", "ftp.example.com"} {
		if !got[want] {
			t.Errorf("expected to crack %q, recovered %v", want, res.Names)
		}
	}
	if got["doesnotexist.example.com"] || got["admin.example.com"] {
		t.Errorf("cracked a non-existent name (false positive): %v", res.Names)
	}
	if len(recovered) != len(res.Names) {
		t.Errorf("OnName fired %d times, result has %d", len(recovered), len(res.Names))
	}
}
