package massdns

import (
	"bufio"
	"errors"
	"os"
)

// IsBlankFile checks if a file is blank
func IsBlankFile(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return true, err
	}
	if stat.Size() <= 1 {
		return true, nil
	}
	return false, nil
}

// DumpWildcardsToFile dumps the wildcard ips list to file
func (c *Client) DumpWildcardsToFile(filename string) error {
	if len(c.wildcardIPMap) == 0 {
		return errors.New("no wildcards")
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	for k := range c.wildcardIPMap {
		_, _ = bw.WriteString(k + "\n")
	}
	defer bw.Flush()
	return nil
}
