package main

import (
	"github.com/projectcalico/fixham/pkg/api"
	"github.com/projectcalico/fixham/pkg/tasks"
)

type Fixham struct {
	api.Component
}

func main() {
	f := &Fixham{
		Component: *api.NewComponent("fixham", "github.com/projectcalico/fixham"),
	}
	f.AddTask(tasks.DefineCleanTask([]string{"bin"}, nil, nil))
	f.AddTask(tasks.DefineStaticChecksTasks(f.DockerGoBuildRunner(), f.Config())...)
	f.AddTask(f.TestTasks()...)
	f.Register()
}
