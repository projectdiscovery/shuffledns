package runner

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
       __        ________        __       
  ___ / /  __ __/ _/ _/ /__  ___/ /__ ___
 (_-</ _ \/ // / _/ _/ / -_)/ _  / _ \(_-<
/___/_//_/\_,_/_//_//_/\__/ \_,_/_//_/___/
`

// version is the current version of shuffledns
const version = `v1.1.0`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates shuffledns
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("shuffledns", version)()
	}
}
