package massdns

import (
	"os"
)

// IsEmptyFile checks if the file is empty.
func IsEmptyFile(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return false, err // Return false along with the error if unable to obtain file stats
	}
	return stat.Size() == 0, nil // Return true if the file size is 0, indicating it is empty
}

// DumpWildcardsToFile dumps the wildcard IPs list to a file.
func (instance *Instance) DumpWildcardsToFile(filename string) error {
	return instance.wildcardStore.SaveToFile(filename)
}

func (instance *Instance) LoadWildcardsFromFile(filename string) error {
	return instance.wildcardStore.LoadFromFile(filename)
}
