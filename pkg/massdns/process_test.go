package massdns

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/shuffledns/internal/simdns"
	"github.com/projectdiscovery/shuffledns/pkg/store"
	"github.com/stretchr/testify/require"
)

func TestResolverHost(t *testing.T) {
	require.Equal(t, "8.8.8.8", resolverHost("8.8.8.8:53"))
	require.Equal(t, "8.8.8.8", resolverHost("8.8.8.8"))
	require.Equal(t, "2001:db8::1", resolverHost("[2001:db8::1]:53"))
	require.Equal(t, "2001:db8::1", resolverHost("2001:db8::1"))
	require.Equal(t, "", resolverHost(""))
}

// TestResolveNamesRecordsResolver resolves names against a local battery and
// checks that the answering resolver is recorded per hostname and rendered in
// the JSON output, while the plain output stays a bare hostname.
func TestResolveNamesRecordsResolver(t *testing.T) {
	battery, err := simdns.Start(2, simdns.Config{BaseLatency: 200 * time.Microsecond, HitPercent: 100})
	require.Nil(t, err)
	defer battery.Stop()

	dir := t.TempDir()
	resolversFile := filepath.Join(dir, "resolvers.txt")
	require.Nil(t, os.WriteFile(resolversFile, []byte(strings.Join(battery.Addrs, "\n")+"\n"), 0o600))

	for _, jsonOutput := range []bool{true, false} {
		outputFile := filepath.Join(dir, fmt.Sprintf("out-%v.txt", jsonOutput))
		instance := &Instance{options: Options{
			ResolversFile:    resolversFile,
			Threads:          100,
			Retries:          3,
			WildcardsThreads: 4,
			Json:             jsonOutput,
			OutputFile:       outputFile,
		}}

		shstore, err := store.New("")
		require.Nil(t, err)

		names := make([]string, 20)
		for i := range names {
			names[i] = fmt.Sprintf("host%d.example.com", i)
		}
		err = instance.resolveNames(context.Background(), shstore, func(out chan<- string) error {
			for _, name := range names {
				out <- name
			}
			return nil
		})
		require.Nil(t, err)

		stored := map[string]struct{}{}
		shstore.Iterate(func(ip string, hostnames []string, counter int) {
			for _, hostname := range hostnames {
				stored[hostname] = struct{}{}
			}
		})
		require.NotEmpty(t, stored)
		for hostname := range stored {
			require.Equal(t, []string{"127.0.0.1"}, shstore.GetResolvers(hostname), hostname)
		}

		require.Nil(t, instance.writeOutput(shstore))
		data, err := os.ReadFile(outputFile)
		require.Nil(t, err)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		require.Len(t, lines, len(stored))
		for _, line := range lines {
			if !jsonOutput {
				_, ok := stored[line]
				require.True(t, ok, "plain output must be a bare hostname: %q", line)
				continue
			}
			var record struct {
				Hostname  string   `json:"hostname"`
				Resolvers []string `json:"resolvers"`
			}
			require.Nil(t, json.Unmarshal([]byte(line), &record), line)
			require.Equal(t, fmt.Sprintf(`{"hostname":%q,"resolvers":["127.0.0.1"]}`, record.Hostname), line)
		}
		shstore.Close()
	}
}
