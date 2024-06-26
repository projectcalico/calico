package main

import (
	"github.com/projectcalico/fixham/pkg/api"
	"github.com/projectcalico/fixham/pkg/goyek"
)

func main() {
	f := api.NewBuilder()
	f.AddTask(goyek.Clean([]string{f.Config().BinDir}, nil))
	f.AddTask(goyek.Lint(f.DockerGoBuildRunner(), f.Config()),
		goyek.CheckFmt(f.DockerGoBuildRunner(), f.Config()),
		goyek.FixFmt(f.DockerGoBuildRunner(), f.Config()),
		goyek.StaticChecks(f.DockerGoBuildRunner(), f.Config()))
	f.Register()
}
