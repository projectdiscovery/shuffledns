package runner

import (
	"errors"
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/mohammadanaraki/shuffledns/pkg/massdns"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Check if a list of resolvers was provided and it exists
	if options.ResolversFile == "" {
		return errors.New("no resolver list provided")
	}
	if _, err := os.Stat(options.ResolversFile); os.IsNotExist(err) {
		return errors.New("resolver file doesn't exists")
	}

	// Check if resolvers are blank
	if blank, err := massdns.IsBlankFile(options.ResolversFile); err == nil {
		if blank {
			return errors.New("blank resolver list specified")
		}
	} else {
		return fmt.Errorf("could not read resolvers: %w", err)
	}

	// Check if the user just wants to perform wildcard filtering on an
	// existing massdns output file.
	if options.MassdnsRaw != "" {
		if options.Domain == "" {
			return errors.New("no domain supplied for massdns input")
		}
		// Return as no more validation required
		return nil
	}

	// Check if a list of domains to resolve has been provided either via list or stdin
	if options.SubdomainsList != "" || options.Stdin {
		// If the optional domain name is not specified, wildcard filtering will be automatically disabled
		if options.Domain == "" {
			gologger.Print().Msgf("Wildcard filtering will be automatically disabled as no domain name has been provided")
		}
		return nil
	}

	// If domain was not provided and stdin was not provided, error out
	if options.Domain == "" && !options.Stdin && options.Wordlist == "" {
		return errors.New("no domain was provided for bruteforce")
	}

	// Check if stdin was given and no
	if options.Wordlist == "" && (options.Stdin || options.SubdomainsList != "") && options.Domain == "" {
		return errors.New("no domain was provided for resolving subdomains")
	}

	// Check for either wordlist or stdin or subdomain list
	if !options.Stdin && options.SubdomainsList == "" && options.Wordlist == "" {
		return errors.New("no wordlist or subdomains given as input")
	}

	// Check for only bruteforce or resolving
	if options.SubdomainsList != "" && options.Wordlist != "" {
		return errors.New("both bruteforce and resolving options specified")
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
