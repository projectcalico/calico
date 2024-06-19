package goyek

import (
	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"

	"github.com/projectcalico/ctl"
)

// client is used to interact with the ctl package.
var client *ctl.Client

// DefaultTask is the default task to run when no task is specified.
var DefaultTask = goyek.Define(goyek.Task{
	Name:  "default",
	Usage: "Default task to run when no task is specified",
	Deps:  []*goyek.DefinedTask{StaticChecks},
})

// Lint is a goyek task that runs the linter using golangci-lint.
var Lint = goyek.Define(goyek.Task{
	Name:  "golangci-lint",
	Usage: "Run linter",
	Action: func(a *goyek.A) {
		GetClient().Lint("")
	},
	Parallel: true,
})

// Fmt is a goyek task that checks code formatting using goimports.
var Fmt = goyek.Define(goyek.Task{
	Name:  "check-fmt",
	Usage: "Check code formatting",
	Action: func(a *goyek.A) {
		a.Log("Checking code formatting.  Any listed files don't match goimports:")
		GetClient().CheckFmt()
	},
	Parallel: true,
})

// FixFmt is a goyek task that fixes code formatting using goimports.
var FixFmt = goyek.Define(goyek.Task{
	Name:  "fix-fmt",
	Usage: "Fix code formatting",
	Action: func(a *goyek.A) {
		GetClient().FixFmt()
	},
})

// StaticChecks is a goyek task that runs the linter and checks code formatting.
var StaticChecks = goyek.Define(goyek.Task{
	Name:  "static-checks",
	Usage: "Run linter and check formatting",
	Deps:  []*goyek.DefinedTask{Lint, Fmt},
})

// DefineDefaultTasks sets the default task dependencies.
func DefineDefaultTasks(tasks ...*goyek.DefinedTask) {
	DefaultTask.SetDeps(tasks)
}

// SetClient sets the client to use for interacting with the ctl package.
func SetClient(packageName string) {
	client = ctl.NewClient(packageName)
}

// GetClient returns the client used to interact with the ctl package.
func GetClient() *ctl.Client {
	return client
}

// Main is the entrypoint for the goyek build system.
//
// It defines common tasks that can be run.
// It also sets the default task to run when no task is specified.
//
// If no default tasks are specified, the DefaultTask runs the "static-checks" task.
func Main(packageName string, defaultTasks ...*goyek.DefinedTask) {
	SetClient(packageName)
	if defaultTasks != nil {
		DefineDefaultTasks(defaultTasks...)
	}
	goyek.SetDefault(DefaultTask)
	boot.Main()
}
