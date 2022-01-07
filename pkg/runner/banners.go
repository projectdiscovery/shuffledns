package runner

import "github.com/projectdiscovery/gologger"

const banner = `
       __        ________        __       
  ___ / /  __ __/ _/ _/ /__  ___/ /__ ___
 (_-</ _ \/ // / _/ _/ / -_)/ _  / _ \(_-<
/___/_//_/\_,_/_//_//_/\__/ \_,_/_//_/___/ v1.0.5								
`

// Version is the current version of naabu
const Version = `v1.0.5`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
