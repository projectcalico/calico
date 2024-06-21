package bootstrap

import (
	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"

	"github.com/projectcalico/fixham/pkg/ctl"
)

var packageName *string

// getPackageName returns the package name.
func getPackageName() string {
	return *packageName
}

// setPackageName sets the package name.
func setPackageName(name string) {
	packageName = &name
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
func Main(packageName string, defaultTasks ...*goyek.DefinedTask) {
	setPackageName(packageName)
	if defaultTasks != nil {
		DefineDefaultTasks(defaultTasks...)
	}
	goyek.SetDefault(DefaultTask)
	boot.Main()
}
