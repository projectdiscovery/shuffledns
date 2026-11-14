package dnsaddr

import (
	"net"
	"testing"
)

func TestWithPort(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 no port", "8.8.8.8", "8.8.8.8:53"},
		{"ipv4 with port", "8.8.8.8:5353", "8.8.8.8:5353"},
		{"ipv4 empty port", "8.8.8.8:", "8.8.8.8:53"},
		{"ipv6 bare", "::1", "[::1]:53"},
		{"ipv6 bare full", "2001:4860:4860::8888", "[2001:4860:4860::8888]:53"},
		{"ipv6 brackets no port", "[::1]", "[::1]:53"},
		{"ipv6 brackets full no port", "[2001:4860:4860::8888]", "[2001:4860:4860::8888]:53"},
		{"ipv6 brackets with port", "[::1]:5353", "[::1]:5353"},
		{"ipv6 brackets port 53", "[2001:4860:4860::8888]:53", "[2001:4860:4860::8888]:53"},
		{"hostname no port", "ns1.example.com", "ns1.example.com:53"},
		{"hostname with port", "ns1.example.com:5353", "ns1.example.com:5353"},
		{"hostname trailing dot", "a.root-servers.net.", "a.root-servers.net.:53"},
		{"surrounding space", "  1.1.1.1  ", "1.1.1.1:53"},
		{"surrounding space ipv6 brackets", " [::1] ", "[::1]:53"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPort(tt.in)
			if got != tt.want {
				t.Fatalf("WithPort(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if _, _, err := net.SplitHostPort(got); err != nil {
				t.Fatalf("WithPort(%q) = %q is not a valid host:port: %v", tt.in, got, err)
			}
			if again := WithPort(got); again != got {
				t.Fatalf("WithPort is not idempotent: %q -> %q", got, again)
			}
		})
	}
}
