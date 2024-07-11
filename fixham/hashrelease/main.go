package main

import (
	"github.com/projectcalico/calico/fixham/pkg/api"
	"github.com/projectcalico/calico/fixham/pkg/goyek"
)

func main() {
	b := api.NewCalicoBuilder()
	b.AddTask(goyek.PinnedVersion(b.Config()),
		goyek.OperatorHashreleaseBuild(b.DockerRunner(), b.Config()),
		goyek.OperatorHashrelease(b.DockerRunner(), b.Config()),
		goyek.HashreleaseBuild(b.Config()),
		goyek.Hashrelease(b.Config()),
	)
	b.Register()
}
