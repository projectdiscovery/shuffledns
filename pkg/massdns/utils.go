package massdns

import (
	"os"
)

// IsBlankFile checks if a file is blank
func IsBlankFile(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return true, err
	}
	return stat.Size() <= 1, nil
}
