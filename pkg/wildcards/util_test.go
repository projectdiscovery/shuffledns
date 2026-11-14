package wildcards

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadResolversFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "resolvers.txt")
	require.Nil(t, os.WriteFile(file, []byte("8.8.8.8\n\n127.0.0.1:5353\n2001:4860:4860::8888\n[2001:4860:4860::8844]:53\n"), 0o600))

	servers, err := LoadResolversFromFile(file)
	require.Nil(t, err)
	require.Equal(t, []string{"8.8.8.8:53", "127.0.0.1:5353", "[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53"}, servers)
}
