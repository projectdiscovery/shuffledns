package iterative

import "net"

// rootServer is a single root nameserver hint (name + addresses).
type rootServer struct {
	name string
	v4   string
	v6   string
}

// rootHints is the static list of the 13 DNS root servers (IANA root hints).
// They bootstrap iterative resolution: the resolver starts here when its
// delegation cache has no closer ancestor for a name. Addresses change very
// rarely; if one is stale the resolver simply rotates to another root.
var rootHints = []rootServer{
	{"a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"},
	{"b.root-servers.net.", "199.9.14.201", "2001:500:200::b"},
	{"c.root-servers.net.", "192.33.4.12", "2001:500:2::c"},
	{"d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"},
	{"e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"},
	{"f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"},
	{"g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"},
	{"h.root-servers.net.", "198.97.190.53", "2001:500:1::53"},
	{"i.root-servers.net.", "192.36.148.17", "2001:7fe::53"},
	{"j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"},
	{"k.root-servers.net.", "193.0.14.129", "2001:7fd::1"},
	{"l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"},
	{"m.root-servers.net.", "202.12.27.33", "2001:dc3::35"},
}

// defaultRootDelegation builds the "." delegation from the static hints. wantV6
// controls whether IPv6 glue is included.
func defaultRootDelegation(wantV6 bool) *delegation {
	d := &delegation{zone: "."}
	for _, r := range rootHints {
		ns := nsEntry{name: r.name}
		if ip := net.ParseIP(r.v4); ip != nil {
			ns.addrs = append(ns.addrs, ip)
		}
		if wantV6 {
			if ip := net.ParseIP(r.v6); ip != nil {
				ns.addrs = append(ns.addrs, ip)
			}
		}
		d.ns = append(d.ns, ns)
	}
	return d
}
