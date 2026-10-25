package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreResolvers(t *testing.T) {
	s, err := New("")
	require.Nil(t, err)
	defer s.Close()

	require.Nil(t, s.Append("1.2.3.4", "a.example.com", "b.example.com"))
	s.AppendResolvers("a.example.com", "8.8.8.8", "")
	s.AppendResolvers("a.example.com", "1.1.1.1", "8.8.8.8")
	s.AppendResolvers("b.example.com", "")

	require.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, s.GetResolvers("a.example.com"))
	require.Nil(t, s.GetResolvers("b.example.com"))
	require.Nil(t, s.GetResolvers("missing.example.com"))

	// resolver records stay separate from the ip -> hostnames index
	var ips []string
	s.Iterate(func(ip string, hostnames []string, counter int) {
		ips = append(ips, ip)
		require.Equal(t, 2, counter)
	})
	require.Equal(t, []string{"1.2.3.4"}, ips)
}
