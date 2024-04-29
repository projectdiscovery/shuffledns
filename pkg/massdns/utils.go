package massdns

import (
	"bufio"
	"errors"
	"os"
)

// IsBlankFile checks if a file is blank (empty).
func IsBlankFile(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return false, err // Return false along with the error if unable to obtain file stats
	}
	return stat.Size() == 0, nil // Return true if the file size is 0, indicating it is empty
}

// DumpWildcardsToFile dumps the wildcard IPs list to a file.
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
		if _, err := bw.WriteString(k + "\n"); err != nil {
			return err // Handle errors immediately when writing to buffer
		}
	}

	return bw.Flush() // Explicitly flush at the end and handle the error if any
}
