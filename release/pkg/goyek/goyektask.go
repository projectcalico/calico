package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	resetTaskName        = "reset"
	releaseNotesTaskName = "release-notes"
	buildTaskName        = "build"
	validateTaskName     = "validate"
)

// GoyekTask represents a Goyek task.
// It is a wrapper around goyek.Task
// that overrides the Desp to be a string list of task names
type GoyekTask struct {
	goyekv2.Task
	Deps []string
}

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

func Validate(cfg *config.Config) *GoyekTask {
	// TODO: Rename task as a pre-release build validation w/ a new task for post-release validation
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  validateTaskName,
			Usage: "Validate release",
			Action: func(a *goyekv2.A) {
				if cfg.IsHashrelease {
					tasks.HashreleaseValidate(cfg)
				} else {
					logrus.Fatal("Only hashrelease is currently supported")
				}
			},
			Parallel: false,
		},
		Deps: []string{operatorPublishTaskName},
	}

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

func Reset(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  resetTaskName,
			Usage: "Reset repo for release",
			Action: func(a *goyekv2.A) {
				tasks.Clean([]string{cfg.OutputDir, cfg.TmpFolderPath()}, nil)
				command.GitInDir(cfg.RepoRootDir, "checkout", "HEAD")
			},
		},
	}
}
