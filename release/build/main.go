package main

import (
	"github.com/projectcalico/calico/release/pkg/api"
	"github.com/projectcalico/calico/release/pkg/goyek"
)

func main() {
	b := api.NewBuilder()
	b.AddTask(
		goyek.PreReleaseValidate(b.Config()),
		goyek.PinnedVersion(b.Config()),
		goyek.OperatorBuild(b.DockerRunner(), b.Config()),
		goyek.OperatorPublish(b.DockerRunner(), b.Config()),
		goyek.Operator(b.Config()),
		goyek.Build(b.Config()),
		goyek.PrePublishValidate(b.Config()),
		goyek.Hashrelease(b.Config()),
		goyek.Reset(b.Config()),
		goyek.HashreleaseGarbageCollect(b.Config()),
		goyek.ReleaseNotes(b.Config()),
	)
	b.Register()
}
