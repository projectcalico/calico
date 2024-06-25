package main

import (
	"github.com/goyek/goyek/v2"
	"github.com/projectcalico/fixham/pkg/tasks"
)

func (f *Fixham) TestTasks() []*goyek.DefinedTask {
	ut := tasks.RegisterTestTask(tasks.NewTestTask(tasks.Unit, func(a *goyek.A) {
		f.DockerGoBuildRunner().RunBashCmd("go test -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./... -v -failfast")
	}, nil, false))
	test := tasks.DefaultTestTask(goyek.Deps{ut})
	return []*goyek.DefinedTask{test, ut}
}
