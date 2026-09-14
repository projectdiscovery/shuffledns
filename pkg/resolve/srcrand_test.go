package resolve

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNewSrcRandFromPrefix(t *testing.T) {
	sr, err := newSrcRandFromPrefix("2001:db8:abcd::/48")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		ip := sr.pick()
		if ip.To16() == nil || ip.To4() != nil {
			t.Fatalf("expected IPv6, got %v", ip)
		}
		// first 48 bits must match 2001:db8:abcd
		if ip[0] != 0x20 || ip[1] != 0x01 || ip[2] != 0x0d || ip[3] != 0xb8 || ip[4] != 0xab || ip[5] != 0xcd {
			t.Fatalf("prefix mismatch: %s", ip)
		}
	}
}

func TestNewSrcRandFromPrefixRejectsIPv4(t *testing.T) {
	if _, err := newSrcRandFromPrefix("192.0.2.0/24"); err == nil {
		t.Fatal("expected error for IPv4 prefix")
	}
}

func TestNewSrcRandFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "srcs.txt")
	content := "# comment\n2001:db8::1\n2001:db8::2/128\n\n192.0.2.1\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sr, err := newSrcRandFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		seen[sr.pick().String()] = true
	}
	if !seen[net.ParseIP("2001:db8::1").String()] || !seen[net.ParseIP("2001:db8::2").String()] {
		t.Fatalf("expected both file addresses, got %v", seen)
	}
	if len(seen) != 2 {
		t.Fatalf("expected only 2 addresses, got %v", seen)
	}
}

func TestNewSrcRandMutualExclusivityInOptions(t *testing.T) {
	_, err := New(Options{
		Resolvers:       []string{"[2001:db8::53]:53"},
		RandSrcIPv6:     "2001:db8::/32",
		RandSrcIPv6File: "x",
		SocketCount:     1,
		Concurrency:     1,
	})
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
}

func TestNewSrcRandIncompatibleWithBind(t *testing.T) {
	_, err := New(Options{
		Resolvers:   []string{"[2001:db8::53]:53"},
		RandSrcIPv6: "2001:db8::/32",
		BindAddr:    "::",
		SocketCount: 1,
		Concurrency: 1,
	})
	if err == nil {
		t.Fatal("expected bind+rand-src error")
	}
}

func TestNewSrcRandRequiresIPv6Resolvers(t *testing.T) {
	_, err := New(Options{
		Resolvers:   []string{"1.1.1.1:53"},
		RandSrcIPv6: "2001:db8::/32",
		SocketCount: 1,
		Concurrency: 1,
	})
	if err == nil {
		t.Fatal("expected IPv6 resolvers required error")
	}
}
