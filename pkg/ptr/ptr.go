// Package ptr generates reverse-DNS (PTR) query names from IP targets, the
// native equivalent of massdns's scripts/ptr.py. Targets may be single IPs,
// CIDR blocks, or inclusive "start-end" ranges, in IPv4 or IPv6.
//
// Each emitted name is the reversed in-addr.arpa (IPv4) or ip6.arpa (IPv6)
// label that a resolver expects for a PTR lookup; e.g. 1.2.3.4 becomes
// 4.3.2.1.in-addr.arpa. These names are fed straight into the resolver with
// query type PTR.
package ptr

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// minIPv6Prefix bounds IPv6 CIDR expansion so a careless /32 doesn't try to
// enumerate an astronomically large space. /112 is 65536 addresses.
const minIPv6Prefix = 112

// ReverseName returns the reverse-DNS name (in-addr.arpa / ip6.arpa) for ip.
func ReverseName(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("nil ip")
	}
	return dns.ReverseAddr(ip.String())
}

// Expand walks every IP described by targets and calls emit with its reverse
// name. emit may return false to stop early. Targets are parsed as, in order:
// an inclusive range "a-b", a CIDR "ip/bits", or a single IP.
func Expand(targets []string, emit func(name string) bool) error {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		stop, err := expandOne(t, emit)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return nil
}

// Stream feeds reverse names produced from targets into out, honouring ctx
// cancellation. It does not close out (the caller owns it).
func Stream(ctx context.Context, targets []string, out chan<- string) error {
	return Expand(targets, func(name string) bool {
		select {
		case <-ctx.Done():
			return false
		case out <- name:
			return true
		}
	})
}

// expandOne handles a single target token. It returns stop=true when emit asked
// to halt.
func expandOne(t string, emit func(string) bool) (bool, error) {
	switch {
	case strings.Contains(t, "-"):
		return expandRange(t, emit)
	case strings.Contains(t, "/"):
		return expandCIDR(t, emit)
	default:
		ip := net.ParseIP(t)
		if ip == nil {
			return false, fmt.Errorf("invalid IP %q", t)
		}
		return emitIP(ip, emit), nil
	}
}

func expandRange(t string, emit func(string) bool) (bool, error) {
	parts := strings.SplitN(t, "-", 2)
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	if startIP == nil || endIP == nil {
		return false, fmt.Errorf("invalid range %q", t)
	}
	start, sv4 := normalize(startIP)
	end, ev4 := normalize(endIP)
	if sv4 != ev4 {
		return false, fmt.Errorf("range %q mixes IPv4 and IPv6", t)
	}
	if compareBytes(start, end) > 0 {
		return false, fmt.Errorf("range %q start is after end", t)
	}
	cur := dupIP(start)
	for {
		if !emit(reverse(cur, sv4)) {
			return true, nil
		}
		if compareBytes(cur, end) == 0 {
			return false, nil
		}
		inc(cur)
	}
}

func expandCIDR(t string, emit func(string) bool) (bool, error) {
	_, ipnet, err := net.ParseCIDR(t)
	if err != nil {
		return false, err
	}
	ones, bits := ipnet.Mask.Size()
	isV4 := bits == 32
	if !isV4 && ones < minIPv6Prefix {
		return false, fmt.Errorf("IPv6 CIDR %q too large; use /%d or longer", t, minIPv6Prefix)
	}
	// network address (already masked by ParseCIDR) and the last address in the
	// block: last = network | ^mask.
	first := dupIP(maskedBase(ipnet.IP, isV4))
	mask := ipnet.Mask
	last := dupIP(first)
	for i := range last {
		last[i] |= ^mask[i]
	}
	cur := dupIP(first)
	for {
		if !emit(reverse(cur, isV4)) {
			return true, nil
		}
		if compareBytes(cur, last) == 0 {
			return false, nil
		}
		inc(cur)
	}
}

// maskedBase normalizes a CIDR network IP to its 4- or 16-byte form.
func maskedBase(ip net.IP, v4 bool) []byte {
	if v4 {
		return dupIP(ip.To4())
	}
	return dupIP(ip.To16())
}

func emitIP(ip net.IP, emit func(string) bool) bool {
	b, v4 := normalize(ip)
	return !emit(reverse(b, v4))
}

// reverse builds the reverse-DNS name for a normalized address. v4 selects the
// 4-byte vs 16-byte interpretation.
func reverse(b []byte, v4 bool) string {
	var ip net.IP
	if v4 {
		ip = net.IPv4(b[0], b[1], b[2], b[3])
	} else {
		ip = make(net.IP, len(b))
		copy(ip, b)
	}
	name, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}
	return name
}

// normalize returns the address in its minimal byte form (4 bytes for IPv4,
// 16 for IPv6) and whether it is IPv4.
func normalize(ip net.IP) ([]byte, bool) {
	if v4 := ip.To4(); v4 != nil {
		return dupIP(v4), true
	}
	return dupIP(ip.To16()), false
}

func dupIP(ip net.IP) []byte {
	b := make([]byte, len(ip))
	copy(b, ip)
	return b
}

// inc increments a big-endian byte-encoded address in place.
func inc(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

func compareBytes(a, b []byte) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}
