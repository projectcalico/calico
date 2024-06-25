package main

import (
	"github.com/projectcalico/fixham/pkg/api"
	"github.com/projectcalico/fixham/pkg/tasks"
)

func main() {
	c := api.NewCalicoBuilder("apiserver")
	c.AddTask(tasks.DefineCleanTask([]string{c.Config().BinDir, ".generate_execs", ".lint-cache"}, nil, nil))
	c.Register()
}
