package wildcards

import (
	"bufio"
	"net"
	"os"
	"strings"
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
		if _, _, err := net.SplitHostPort(text); err == nil {
			servers = append(servers, text)
			continue
		}
		servers = append(servers, net.JoinHostPort(strings.Trim(text, "[]"), "53"))
	}
	return servers, nil
}
