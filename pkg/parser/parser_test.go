package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParserParseSingleIP(t *testing.T) {
	sampleData := `docs.bugbounty.com. A 185.199.111.153`

	var domain string
	var ip []string
	err := ParseReader(strings.NewReader(sampleData), func(Domain string, IP []string, resolver string) error {
		domain = Domain
		ip = IP
		return nil
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "docs.bugbounty.com", domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153"}, ip, "Could not get ip")
}

func TestParserParseMultipleDomains(t *testing.T) {
	sampleData := `
docs.bugbounty.com. A 185.199.111.153

docs.hackerone.com. A 185.199.111.152`

	var domain []string
	var ip []string
	err := ParseReader(strings.NewReader(sampleData), func(Domain string, IP []string, resolver string) error {
		domain = append(domain, Domain)
		ip = append(ip, IP[0])
		return nil
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, []string{"docs.bugbounty.com", "docs.hackerone.com"}, domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153", "185.199.111.152"}, ip, "Could not get ip")
}

func TestParserParseMultipleIPCNAME(t *testing.T) {
	sampleData := `
docs.hackerone.com. CNAME hacker0x01.github.io.
hacker0x01.github.io. A 185.199.111.153
hacker0x01.github.io. A 185.199.108.153
hacker0x01.github.io. A 185.199.109.153
hacker0x01.github.io. A 185.199.110.153`

	var domain string
	var ip []string
	err := ParseReader(strings.NewReader(sampleData), func(Domain string, IP []string, resolver string) error {
		domain = Domain
		ip = IP
		return nil
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "docs.hackerone.com", domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153", "185.199.108.153", "185.199.109.153", "185.199.110.153"}, ip, "Could not get ip")
}

func TestParserParseMultipleCNAMEIP(t *testing.T) {
	sampleData := `
docs.bugbounty.com. CNAME bugbounty.github.io.
bugbounty.github.io. CNAME bugbounty-local.herokudns.io.
bugbounty-local.herokudns.io. A 185.199.111.153`

	var domain string
	var ip []string
	err := ParseReader(strings.NewReader(sampleData), func(Domain string, IP []string, resolver string) error {
		domain = Domain
		ip = IP
		return nil
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "docs.bugbounty.com", domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153"}, ip, "Could not get ip")
}

// TestParserParseWithResolverMeta exercises massdns output produced
// with the `r` simple flag (-o Snlr). Each reply block is prefixed
// with a metadata line containing the resolver IP that answered.
func TestParserParseWithResolverMeta(t *testing.T) {
	sampleData := `8.8.8.8:53 1734567890 NOERROR docs.bugbounty.com.  A
docs.bugbounty.com. A 185.199.111.153

1.1.1.1:53 1734567891 NOERROR docs.hackerone.com.  A
docs.hackerone.com. A 185.199.111.152`

	type result struct {
		domain   string
		ip       []string
		resolver string
	}
	var results []result
	err := ParseReader(strings.NewReader(sampleData), func(domain string, ip []string, resolver string) error {
		results = append(results, result{domain: domain, ip: ip, resolver: resolver})
		return nil
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, []result{
		{domain: "docs.bugbounty.com", ip: []string{"185.199.111.153"}, resolver: "8.8.8.8"},
		{domain: "docs.hackerone.com", ip: []string{"185.199.111.152"}, resolver: "1.1.1.1"},
	}, results)
}

// TestParserParseWithResolverMetaIPv6 ensures IPv6 resolver metadata
// lines (massdns wraps the address in square brackets) are parsed
// correctly and only the address is forwarded to the callback.
func TestParserParseWithResolverMetaIPv6(t *testing.T) {
	sampleData := `[2001:4860:4860::8888]:53 1734567890 NOERROR docs.bugbounty.com.  A
docs.bugbounty.com. A 185.199.111.153`

	var resolver string
	err := ParseReader(strings.NewReader(sampleData), func(domain string, ip []string, r string) error {
		resolver = r
		return nil
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "2001:4860:4860::8888", resolver)
}
