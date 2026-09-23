package resolve

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
)

// srcRand picks a random IPv6 source address for each query, either from a
// prefix (massdns --rand-src-ipv6) or from a file of addresses
// (--rand-src-ipv6-file). Used with Linux raw IPv6 UDP sockets + IPV6_HDRINCL.
type srcRand struct {
	fromFile bool
	base     net.IP // 16-byte network base (prefix bits set, host zeroed)
	bits     int
	addrs    []net.IP
}

func newSrcRandFromPrefix(spec string) (*srcRand, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty IPv6 prefix")
	}
	if !strings.Contains(spec, "/") {
		spec += "/128"
	}
	ip, ipnet, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid --rand-src-ipv6 %q: %w", spec, err)
	}
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("--rand-src-ipv6 requires an IPv6 prefix")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("--rand-src-ipv6 requires an IPv6 prefix")
	}
	base := make(net.IP, 16)
	copy(base, ip.Mask(ipnet.Mask).To16())
	return &srcRand{base: base, bits: ones}, nil
}

func newSrcRandFromFile(path string) (*srcRand, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var addrs []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// allow optional /prefix; take address only
		if i := strings.IndexByte(line, '/'); i >= 0 {
			line = line[:i]
		}
		ip := net.ParseIP(line)
		if ip == nil || ip.To4() != nil {
			continue
		}
		addrs = append(addrs, ip.To16())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no valid IPv6 addresses in %s", path)
	}
	return &srcRand{fromFile: true, addrs: addrs}, nil
}

func (s *srcRand) pick() net.IP {
	if s.fromFile {
		return s.addrs[rand.IntN(len(s.addrs))]
	}
	out := make(net.IP, 16)
	copy(out, s.base)
	hostBits := 128 - s.bits
	if hostBits <= 0 {
		return out
	}
	// Randomize the host portion (same approach as massdns: full trailing
	// bytes randomly, plus a partial byte for leftover bits).
	fullBytes := hostBits / 8
	remBits := hostBits % 8
	if remBits > 0 {
		idx := 16 - fullBytes - 1
		mask := byte((1 << remBits) - 1)
		out[idx] = (out[idx] & ^mask) | (byte(rand.Uint32()) & mask)
	}
	for i := 0; i < fullBytes; i++ {
		out[16-fullBytes+i] = byte(rand.Uint32())
	}
	return out
}
