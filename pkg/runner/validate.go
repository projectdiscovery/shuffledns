package runner

import (
	"errors"

	"github.com/projectdiscovery/gologger"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// If domain was not provided and stdin was not provided, error out
	if options.Domain == "" && !options.Stdin && options.Wordlist == "" {
		return errors.New("no domain was provided for bruteforce")
	}

	// Check if stdin was given and no
	if options.Wordlist == "" && (options.Stdin || options.SubdomainsList != "") && options.Domain == "" {
		return errors.New("no domain was provided for resolving subdomains")
	}

	// Check if a list of resolvers was provided
	if options.ResolversFile == "" {
		return errors.New("no resolver list provided")
	}

	// Check for either wordlist or stdin or subdomain list
	if !options.Stdin && options.SubdomainsList == "" && options.Wordlist == "" {
		return errors.New("no wordlist or subdomains given as input")
	}

	// Check for only bruteforce or resolving
	if options.SubdomainsList != "" && options.Wordlist != "" {
		return errors.New("both bruteforce and resolving options specified")
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}
	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.NoColor {
		gologger.UseColors = false
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
