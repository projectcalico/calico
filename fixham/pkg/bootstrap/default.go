package bootstrap

import (
	"github.com/goyek/goyek/v2"
)

// DefaultTask is the default task to run when no task is specified.
var DefaultTask = goyek.Define(goyek.Task{
	Name:  "default",
	Usage: "Default task to run when no task is specified",
	Deps:  []*goyek.DefinedTask{StaticChecks},
})

// DefineDefaultTasks sets the default task dependencies.
func DefineDefaultTasks(tasks ...*goyek.DefinedTask) {
	DefaultTask.SetDeps(tasks)
}
