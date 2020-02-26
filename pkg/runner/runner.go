package runner

import "os"

// Runner is a client for running the enumeration process.
type Runner struct {
}

// New creates a new client for running enumeration process.
func New() *Runner {

}

// findBinary searches for massdns binary in various pre-defined paths
// only linux and macos paths are supported rn
func (r *Runner) findBinary() string {
	locations := []string{
		"/usr/bin/massdns",
		"/usr/local/bin/massdns",
	}

	for _, file := range locations {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			return file
		}
	}
	return ""
}
