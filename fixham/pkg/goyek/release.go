package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/pkg/tasks"
)

const (
	releaseNotesTaskName = "release-notes"
)

func ReleaseNotes(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  releaseNotesTaskName,
			Usage: "Generate release notes",
			Action: func(a *goyekv2.A) {
				tasks.ReleaseNotes(cfg)
			},
			Parallel: false,
		},
	}
}
