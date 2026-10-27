package ptr

import (
	"context"
	"net"
	"testing"
)

func collect(t *testing.T, targets ...string) []string {
	t.Helper()
	var got []string
	if err := Expand(targets, func(name string) bool {
		got = append(got, name)
		return true
	}); err != nil {
		t.Fatalf("Expand(%v): %v", targets, err)
	}
	return got
}

func TestReverseName(t *testing.T) {
	name, err := ReverseName(net.ParseIP("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if name != "4.3.2.1.in-addr.arpa." {
		t.Fatalf("got %q", name)
	}
}

func TestSingleIP(t *testing.T) {
	got := collect(t, "192.0.2.5")
	if len(got) != 1 || got[0] != "5.2.0.192.in-addr.arpa." {
		t.Fatalf("got %v", got)
	}
}

func TestExpandCIDRv4(t *testing.T) {
	got := collect(t, "192.0.2.0/30")
	want := []string{
		"0.2.0.192.in-addr.arpa.",
		"1.2.0.192.in-addr.arpa.",
		"2.2.0.192.in-addr.arpa.",
		"3.2.0.192.in-addr.arpa.",
	}
	if len(got) != len(want) {
		t.Fatalf("count: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestExpandRange(t *testing.T) {
	got := collect(t, "192.0.2.1-192.0.2.3")
	if len(got) != 3 {
		t.Fatalf("count: got %d (%v)", len(got), got)
	}
	if got[0] != "1.2.0.192.in-addr.arpa." || got[2] != "3.2.0.192.in-addr.arpa." {
		t.Fatalf("got %v", got)
	}
}

func TestExpandCIDRv6Small(t *testing.T) {
	got := collect(t, "2001:db8::/126")
	if len(got) != 4 {
		t.Fatalf("count: got %d (%v)", len(got), got)
	}
	for _, n := range got {
		if len(n) < len("ip6.arpa.") || n[len(n)-len("ip6.arpa."):] != "ip6.arpa." {
			t.Fatalf("not an ip6.arpa name: %q", n)
		}
	}
}

func TestExpandCIDRv6TooLarge(t *testing.T) {
	err := Expand([]string{"2001:db8::/32"}, func(string) bool { return true })
	if err == nil {
		t.Fatal("expected error for oversized IPv6 CIDR")
	}
}

func TestEarlyStop(t *testing.T) {
	count := 0
	err := Expand([]string{"10.0.0.0/8"}, func(string) bool {
		count++
		return count < 5 // stop after 5
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("expected early stop at 5, got %d", count)
	}
}

func TestInvalidTarget(t *testing.T) {
	if err := Expand([]string{"not-an-ip"}, func(string) bool { return true }); err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestStreamCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan string, 2)
	done := make(chan error, 1)
	go func() { done <- Stream(ctx, []string{"10.0.0.0/8"}, out) }()

	<-out // consume one
	cancel()
	// drain so Stream isn't blocked on send
	go func() {
		for range out {
		}
	}()
	if err := <-done; err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
}
