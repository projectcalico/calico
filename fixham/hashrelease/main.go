package main

import (
	"github.com/projectcalico/calico/fixham/pkg/api"
	"github.com/projectcalico/calico/fixham/pkg/goyek"
)

func main() {
	b := api.NewBuilder()
	b.AddTask(goyek.PinnedVersion(b.Config(), b.Output()),
		goyek.OperatorHashreleaseBuild(b.DockerRunner(), b.Config(), b.Output()),
		goyek.OperatorHashreleasePublish(b.DockerRunner(), b.Config(), b.Output()),
		goyek.OperatorHashrelease(b.DockerRunner(), b.Config(), b.Output()),
		goyek.HashreleaseBuild(b.Config(), b.Output()),
		goyek.HashreleaseValidate(b.Config(), b.Output()),
		goyek.Hashrelease(b.Config(), b.Output()),
		goyek.HashreleaseClean(b.Output()),
		goyek.HashreleaseGarbageCollect(b.Config()),
		goyek.HashreleaseNotes(b.Config(), b.Output()),
	)
	b.Register()
}
