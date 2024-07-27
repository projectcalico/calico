package main

import (
	"github.com/projectcalico/calico/release/pkg/api"
	"github.com/projectcalico/calico/release/pkg/goyek"
)

func main() {
	b := api.NewBuilder()
	b.AddTask(goyek.PinnedVersion(b.Config()),
		goyek.OperatorBuild(b.DockerRunner(), b.Config()),
		goyek.OperatorPublish(b.DockerRunner(), b.Config()),
		goyek.Operator(b.Config()),
		goyek.HashreleaseBuild(b.Config()),
		goyek.HashreleaseValidate(b.Config()),
		goyek.Hashrelease(b.Config()),
		goyek.Clean(b.Config()),
		goyek.HashreleaseGarbageCollect(b.Config()),
		goyek.ReleaseNotes(b.Config()),
	)
	b.Register()
}
