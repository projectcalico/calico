package main

import (
	"github.com/projectcalico/fixham/pkg/api"
	"github.com/projectcalico/fixham/pkg/tasks"
)

func main() {
	f := api.NewBuilder("fixham", "github.com/projectcalico/fixham")
	f.AddTask(tasks.DefineCleanTask([]string{"bin"}, nil, nil))
	f.AddTask(tasks.DefineStaticChecksTasks(f.DockerGoBuildRunner(), f.Config())...)
	f.AddTask(TestTasks(f)...)
	f.Register()
}
