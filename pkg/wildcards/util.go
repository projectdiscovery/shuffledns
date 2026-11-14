package wildcards

import (
	"bufio"
	"os"
	"strings"

	"github.com/projectdiscovery/shuffledns/pkg/dnsaddr"
)

func LoadResolversFromFile(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		// keep an explicit port, default to 53 otherwise (IPv6 safe)
		servers = append(servers, dnsaddr.WithPort(text))
	}
	return servers, nil
}
