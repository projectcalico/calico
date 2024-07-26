package main

import (
	"github.com/projectcalico/calico/fixham/pkg/api"
	"github.com/projectcalico/calico/fixham/pkg/goyek"
)

func main() {
	b := api.NewBuilder()
	b.AddTask(goyek.PinnedVersion(b.Config()),
		goyek.OperatorHashreleaseBuild(b.DockerRunner(), b.Config()),
		goyek.OperatorHashreleasePublish(b.DockerRunner(), b.Config()),
		goyek.OperatorHashrelease(),
		goyek.HashreleaseBuild(b.Config()),
		goyek.HashreleaseValidate(b.Config()),
		goyek.Hashrelease(b.Config()),
		goyek.HashreleaseClean(b.Config()),
		goyek.HashreleaseGarbageCollect(b.Config()),
		goyek.HashreleaseNotes(b.Config()),
	)
	b.Register()
}
