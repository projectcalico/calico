package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	buildTaskName        = "build"
	resetTaskName        = "reset"
	releaseNotesTaskName = "release-notes"
)

// GoyekTask represents a Goyek task.
// It is a wrapper around goyek.Task
// that overrides the Desp to be a string list of task names
type GoyekTask struct {
	goyekv2.Task
	Deps []string
}

// Build creates a Goyek task for building a release
func Build(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  buildTaskName,
			Usage: "Build release",
			Action: func(a *goyekv2.A) {
				if cfg.IsHashrelease {
					tasks.HashreleaseBuild(cfg)
				} else {
					logrus.Fatal("Only hashrelease is currently supported")
				}
				tasks.ReleaseNotes(cfg)
				logrus.Infof("%s build complete.", cfg.ReleaseType())
			},
			Parallel: false,
		},
		Deps: []string{operatorBuildTaskName},
	}
}

// ReleaseNotes creates a Goyek task for generating release notes
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

// Reset creates a Goyek task for resetting the repo for release
func Reset(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  resetTaskName,
			Usage: "Reset repo for release",
			Action: func(a *goyekv2.A) {
				tasks.CleanFiles([]string{cfg.OutputDir, cfg.TmpFolderPath()}...)
				tasks.ResetRepo(cfg.RepoRootDir)
			},
		},
	}
}
