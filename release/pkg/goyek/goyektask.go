package goyek

import (
	"path/filepath"

	"github.com/goyek/goyek/v2"
	goyekv2 "github.com/goyek/goyek/v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	cleanTaskName        = "clean"
	releaseNotesTaskName = "release-notes"
)

// GoyekTask represents a Goyek task.
// It is a wrapper around goyek.Task
// that overrides the Desp to be a string list of task names
type GoyekTask struct {
	goyek.Task
	Deps []string
}

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

func Clean(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  cleanTaskName,
			Usage: "Clean up tmp dirs & artifacts",
			Action: func(a *goyekv2.A) {
				tasks.Clean([]string{cfg.OutputDir, filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "tmp")}, nil)
			},
		},
	}
}
