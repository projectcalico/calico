package main

import (
	"github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/pkg/tasks"
)

func (f *Fixham) TestTasks() []*goyek.DefinedTask {
	ut := tasks.RegisterTestTask(tasks.NewTestTask(tasks.Unit, func(a *goyek.A) {
		err := f.DockerGoBuildRunner().
			RunBashCmd("go test -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./... -v -failfast")
		if err != nil {
			logrus.WithError(err).Fatal("Unit tests failed")
		}
	}, nil, false))
	test := tasks.DefaultTestTask(goyek.Deps{ut})
	return []*goyek.DefinedTask{test, ut}
}
