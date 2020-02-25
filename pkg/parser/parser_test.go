package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParserParseSingleIP(t *testing.T) {
	sampleData := `
;; Server: 9.9.9.10:53
;; Size: 134
;; Unix time: 1582650534
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44677
;; flags: qr rd ra ; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
docs.bugbounty.com. IN A

;; ANSWER SECTION:
docs.bugbounty.com. 3600 IN A 185.199.111.153`

	var domain string
	var ip []string
	err := Parse(strings.NewReader(sampleData), func(Domain string, IP []string) {
		domain = Domain
		ip = IP
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "docs.bugbounty.com", domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153"}, ip, "Could not get ip")
}

func TestParserParseMultipleDomains(t *testing.T) {
	sampleData := `
;; Server: 9.9.9.10:53
;; Size: 134
;; Unix time: 1582650534
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44677
;; flags: qr rd ra ; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
docs.bugbounty.com. IN A

;; ANSWER SECTION:
docs.bugbounty.com. 3600 IN A 185.199.111.153

;; Server: 9.9.9.10:53
;; Size: 134
;; Unix time: 1582650534
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44677
;; flags: qr rd ra ; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
docs.hackerone.com. IN A

;; ANSWER SECTION:
docs.hackerone.com. 3600 IN A 185.199.111.152`

	var domain []string
	var ip []string
	err := Parse(strings.NewReader(sampleData), func(Domain string, IP []string) {
		domain = append(domain, Domain)
		ip = append(ip, IP[0])
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, []string{"docs.bugbounty.com", "docs.hackerone.com"}, domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153", "185.199.111.152"}, ip, "Could not get ip")
}

func TestParserParseMultipleIPCNAME(t *testing.T) {
	sampleData := `
;; Server: 9.9.9.10:53
;; Size: 134
;; Unix time: 1582650534
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44677
;; flags: qr rd ra ; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
docs.hackerone.com. IN A

;; ANSWER SECTION:
docs.hackerone.com. 300 IN CNAME hacker0x01.github.io.
hacker0x01.github.io. 3600 IN A 185.199.111.153
hacker0x01.github.io. 3600 IN A 185.199.108.153
hacker0x01.github.io. 3600 IN A 185.199.109.153
hacker0x01.github.io. 3600 IN A 185.199.110.153`

	var domain string
	var ip []string
	err := Parse(strings.NewReader(sampleData), func(Domain string, IP []string) {
		domain = Domain
		ip = IP
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "docs.hackerone.com", domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153", "185.199.108.153", "185.199.109.153", "185.199.110.153"}, ip, "Could not get ip")
}

func TestParserParseMultipleCNAMEIP(t *testing.T) {
	sampleData := `
;; Server: 9.9.9.10:53
;; Size: 134
;; Unix time: 1582650534
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44677
;; flags: qr rd ra ; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
docs.bugbounty.com. IN A

;; ANSWER SECTION:
docs.bugbounty.com. 300 IN CNAME bugbounty.github.io.
bugbounty.github.io. 300 IN CNAME bugbounty-local.herokudns.io.
bugbounty-local.herokudns.io. 3600 IN A 185.199.111.153`

	var domain string
	var ip []string
	err := Parse(strings.NewReader(sampleData), func(Domain string, IP []string) {
		domain = Domain
		ip = IP
	})
	require.Nil(t, err, "Could not parse sample data")
	require.Equal(t, "docs.bugbounty.com", domain, "Could not get domain")
	require.Equal(t, []string{"185.199.111.153"}, ip, "Could not get ip")
}
