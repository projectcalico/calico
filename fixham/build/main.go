package main

import (
	"github.com/projectcalico/fixham/pkg/api"
	"github.com/projectcalico/fixham/pkg/tasks"
)

type Fixham struct {
	api.Component
}

func (f *Fixham) Tasks() {
	tasks.DefineCleanTask([]string{"bin"}, nil, nil)
	tasks.DefineStaticChecksTasks(f.DockerGoBuildRunner(), f.Config())
}

func (f *Fixham) Register() {
	f.Tasks()
	f.Component.Register()
}

func main() {
	f := &Fixham{
		Component: *api.NewComponent("fixham", "github.com/projectcalico/fixham"),
	}
	f.Register()
}
