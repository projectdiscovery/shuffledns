package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	massdnsRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	if err := massdnsRunner.RunEnumeration(); err != nil {
		massdnsRunner.Close()
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	massdnsRunner.Close()
}
