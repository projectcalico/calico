package goyek

import (
	_goyek "github.com/goyek/goyek/v2"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/docker"
	"github.com/projectcalico/calico/fixham/pkg/tasks"
)

const (
	pinnedVersionTaskName    = "pinned-version"
	operatorBuildTaskName    = "operator/build"
	operatorTaskName         = "operator"
	hashreleaseBuildTaskName = "build"
	hashreleaseTaskName      = "publish"
	hashreleaseCleanTaskName = "clean"
)

func PinnedVersion(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  pinnedVersionTaskName,
			Usage: "Generate pinned version file",
			Action: func(a *_goyek.A) {
				tasks.PinnedVersion(cfg)
			},
			Parallel: false,
		},
	}
}

func OperatorHashreleaseBuild(runner *docker.DockerRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  operatorBuildTaskName,
			Usage: "Build and tag operator hashrelease",
			Action: func(a *_goyek.A) {
				tasks.OperatorHashreleaseBuild(runner, cfg)
			},
			Parallel: false,
		},
		Deps: []string{pinnedVersionTaskName},
	}
}

func OperatorHashrelease(runner *docker.DockerRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  operatorTaskName,
			Usage: "Build and publish operator hashrelease",
			Action: func(a *_goyek.A) {
				tasks.OperatorHashreleasePush(runner, cfg)
			},
			Parallel: false,
		},
		Deps: []string{operatorBuildTaskName},
	}
}

func HashreleaseBuild(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  hashreleaseBuildTaskName,
			Usage: "Build hashrelease",
			Action: func(a *_goyek.A) {
				tasks.HashreleaseBuild(cfg)
				tasks.HashreleaseNotes(cfg)
				// TODO: either validate hashrelease here or in the publish task
			},
			Parallel: false,
		},
		Deps: []string{operatorTaskName},
	}
}

func Hashrelease(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  hashreleaseTaskName,
			Usage: "Build and publish hashrelease",
			Action: func(a *_goyek.A) {
				tasks.HashreleasePush(cfg)
				tasks.HashreleaseClean(cfg)
				// TODO: restore repo to original state
			},
			Parallel: false,
		},
		Deps: []string{hashreleaseBuildTaskName},
	}
}

func HashreleaseClean(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  hashreleaseCleanTaskName,
			Usage: "Clean up older hashreleases",
			Action: func(a *_goyek.A) {
				tasks.HashreleaseClean(cfg)
			},
			Parallel: false,
		},
	}
}

func HashreleaseNotes(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  releaseNotesTaskName,
			Usage: "Generate release notes",
			Action: func(a *_goyek.A) {
				tasks.HashreleaseNotes(cfg)
			},
			Parallel: false,
		},
	}
}
