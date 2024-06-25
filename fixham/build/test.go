package main

import (
	"github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/pkg/api"
	"github.com/projectcalico/fixham/pkg/tasks"
)

func TestTasks(b *api.Builder) []*goyek.DefinedTask {
	ut := tasks.RegisterTestTask(tasks.NewTestTask(tasks.Unit, func(a *goyek.A) {
		err := b.DockerGoBuildRunner().
			RunBashCmd("go test -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./... -v -failfast")
		if err != nil {
			logrus.WithError(err).Fatal("Unit tests failed")
		}
	}, nil, false))
	test := tasks.DefaultTestTask(goyek.Deps{ut})
	return []*goyek.DefinedTask{test, ut}
}
