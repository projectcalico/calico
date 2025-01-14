package version

import "fmt"

// BuildVersion stores the SemVer for the given build
var BuildVersion string

// BuildDate stores the date of the build
var BuildDate string

// GitDescription stores the tag description
var GitDescription string

// GitRevision stores git commit hash for the given build
var GitRevision string

// Version prints version and build information.
func Version() {
	fmt.Println("Version:     ", BuildVersion)
	fmt.Println("Build date:  ", BuildDate)
	fmt.Println("Git tag ref: ", GitDescription)
	fmt.Println("Git commit:  ", GitRevision)
}
