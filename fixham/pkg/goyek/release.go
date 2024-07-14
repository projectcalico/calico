package goyek

import (
	_goyek "github.com/goyek/goyek/v2"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/pkg/tasks"
)

const (
	releaseNotesTaskName = "release-notes"
)

func ReleaseNotes(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  releaseNotesTaskName,
			Usage: "Generate release notes",
			Action: func(a *_goyek.A) {
				tasks.ReleaseNotes(cfg)
			},
			Parallel: false,
		},
	}
}
