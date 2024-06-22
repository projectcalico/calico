package bootstrap

import (
	"flag"
	"fmt"
	"os"

	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"

	"github.com/projectcalico/fixham/pkg/ctl"
)

var (
	pkgName  *string
	rootBind *string

	bootstapPackageName string
)

// getPackageName returns the package name.
func getPackageName() string {
	return *pkgName
}

// NewGoBuildRunner returns a new instance of the GoBuildRunner.
func NewGoBuildRunner() *ctl.GoBuildRunner {
	return ctl.NewGoBuildRunner(getPackageName())
}

// Main is the entrypoint for the goyek build system.
//
// It defines common tasks that can be run.
// It also sets the default task to run when no task is specified.
//
// If no default tasks are specified, the DefaultTask runs the "static-checks" task.
func Main(packageName string, rootVolume string) {
	flag.StringVar(&bootstapPackageName, "package", LookupEnv("PACKAGE_NAME", packageName), "The package name to use")
	pkgName = &bootstapPackageName
	if rootVolume == "" {
		currentDir, _ := os.Getwd()
		rootVolume = fmt.Sprintf("%s:/go/src/%s:rw", currentDir, *pkgName) // TODO: read from config
	}
	rootBind = &rootVolume
	goyek.SetDefault(DefaultTask)
	boot.Main()
}

func LookupEnv(key, defaultValue string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultValue
}
