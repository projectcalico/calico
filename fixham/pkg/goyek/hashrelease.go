package goyek

import (
	_goyek "github.com/goyek/goyek/v2"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/docker"
	"github.com/projectcalico/calico/fixham/pkg/tasks"
)

func PinnedVersion(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  "pinned-version",
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
			Name:  "operator/build",
			Usage: "Build and tag operator hashrelease",
			Action: func(a *_goyek.A) {
				tasks.OperatorHashreleaseBuild(runner, cfg)
			},
			Parallel: false,
		},
		Deps: []string{"pinned-version"},
	}
}

func OperatorHashrelease(runner *docker.DockerRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  "operator",
			Usage: "Build and publish operator hashrelease",
			Action: func(a *_goyek.A) {
				tasks.OperatorHashreleasePush(runner, cfg)
			},
			Parallel: false,
		},
		Deps: []string{"operator/build"},
	}
}

func HashreleaseBuild(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  "build",
			Usage: "Build hashrelease",
			Action: func(a *_goyek.A) {
				tasks.HashreleaseBuild(cfg)
			},
			Parallel: false,
		},
		Deps: []string{"operator"},
	}
}

func Hashrelease(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: _goyek.Task{
			Name:  "publish",
			Usage: "Build and publish hashrelease",
			Action: func(a *_goyek.A) {
				tasks.HashreleasePush(cfg)
			},
			Parallel: false,
		},
		Deps: []string{"build"},
	}
}
