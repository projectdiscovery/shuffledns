package runner

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/shuffledns/pkg/massdns"
	fileutil "github.com/projectdiscovery/utils/file"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Check if a list of resolvers was provided and it exists
	if !fileutil.FileExists(options.ResolversFile) {
		return errors.New("resolver file doesn't exists")
	}

	// Check if resolvers are blank
	if blank, err := massdns.IsEmptyFile(options.ResolversFile); err == nil {
		if blank {
			return errors.New("empty resolver list specified")
		}
	} else {
		return fmt.Errorf("could not read resolvers: %w", err)
	}

	switch options.Mode {
	case "bruteforce":
		if options.Wordlist == "" {
			return errors.New("wordlist not specified")
		}
		if len(options.Domains) == 0 {
			return errors.New("domain not specified")
		}
	case "resolve":
		if options.SubdomainsList == "" && !fileutil.HasStdin() {
			return errors.New("specify subdomains to resolve via flag or stdin")
		}
		// If the optional domain name is not specified, wildcard filtering will be automatically disabled
		if len(options.Domains) == 0 {
			gologger.Print().Msgf("Wildcard filtering will be automatically disabled as no domain name has been provided")
		}
	case "filter":
		// Check if the user just wants to perform wildcard filtering on an existing massdns output file.
		if options.MassdnsRaw == "" {
			return errors.New("no massdns input file specified")
		}
		if len(options.Domains) == 0 {
			return errors.New("domain not specified")
		}
	default:
		return errors.New("execution mode not specified")
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
