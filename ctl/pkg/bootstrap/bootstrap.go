package bootstrap

import (
	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"
)

var packageName *string

func GetPackageName() string {
	return *packageName
}

func setPackageName(name string) {
	packageName = &name
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
