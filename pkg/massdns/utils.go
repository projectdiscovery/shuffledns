package massdns

import (
	"net"

	iputil "github.com/projectdiscovery/utils/ip"
)

// shouldFilterIP determines if an IP should be filtered based on the options.
// It always filters 0.0.0.0 and IPs ending in .0 or .255 (network/broadcast addresses),
// and filters internal IPs if FilterInternalIPs is enabled.
func (instance *Instance) shouldFilterIP(ip string) bool {
	// Always filter 0.0.0.0
	if ip == "0.0.0.0" {
		return true
	}

	// Parse IP to check for .0 and .255 endings
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		if ipv4 := parsedIP.To4(); ipv4 != nil {
			// Always filter network (.0) and broadcast (.255) addresses
			if ipv4[3] == 0 || ipv4[3] == 255 {
				return true
			}
		}
	}

	// Filter internal IPs if flag is set
	if instance.options.FilterInternalIPs {
		return iputil.IsInternal(ip)
	}

	return false
}
