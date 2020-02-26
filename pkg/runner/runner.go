package runner

import "os"

// Runner is a client for running the enumeration process.
type Runner struct {
	options *Options
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	// Setup the massdns binary path if none was give.
	// If no valid path found, return an error
	if options.MassdnsPath == "" {
		options.MassdnsPath = runner.findBinary()
		if options.MassdnsPath == "" {
			return nil, errors.New("could not find massdns binary")
		}
	}

	return runner, nil
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
