// Package dnsaddr normalizes DNS server addresses to the host:port form that
// the net package dials.
package dnsaddr

import (
	"net"
	"strings"
)

// DefaultPort is the port used when an address has none.
const DefaultPort = "53"

// WithPort returns addr as host:port, adding DefaultPort when addr has no port.
// It accepts IPv4, IPv6 with or without brackets, and host names, each with or
// without a port. An address that already has a port is returned unchanged.
//
//	8.8.8.8        -> 8.8.8.8:53
//	::1            -> [::1]:53
//	[::1]          -> [::1]:53
//	[::1]:5353     -> [::1]:5353
//	ns1.example    -> ns1.example:53
func WithPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if port == "" {
			return net.JoinHostPort(host, DefaultPort)
		}
		return addr
	}
	// A bracketed IPv6 address without a port ("[::1]") fails SplitHostPort
	// with "missing port". Drop the brackets first, or JoinHostPort adds a
	// second pair ("[[::1]]:53").
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}
	return net.JoinHostPort(addr, DefaultPort)
}
