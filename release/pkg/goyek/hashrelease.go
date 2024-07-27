package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	pinnedVersionTaskName             = "hashrelease/pinned-version"
	hashreleaseBuildTaskName          = "hashrelease/build"
	hashreleaseValidateTaskName       = "hashrelease/validate"
	hashreleaseTaskName               = "hashrelease/publish"
	hashreleaseGarbageCollectTaskName = "hashrelease/garbage-collect"
)

func PinnedVersion(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  pinnedVersionTaskName,
			Usage: "Generate pinned version file",
			Action: func(a *goyekv2.A) {
				tasks.PinnedVersion(cfg)
			},
			Parallel: false,
		},
	}
}

func HashreleaseBuild(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseBuildTaskName,
			Usage: "Build hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.HashreleaseBuild(cfg)
				tasks.ReleaseNotes(cfg)
				logrus.Info("Hashrelease build complete, run 'validate' to check the hashrelease.")
			},
			Parallel: false,
		},
		Deps: []string{operatorBuildTaskName},
	}
}

func HashreleaseValidate(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseValidateTaskName,
			Usage: "Validate hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.HashreleaseValidate(cfg)
			},
			Parallel: false,
		},
		Deps: []string{operatorPublishTaskName},
	}

}

func Hashrelease(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseTaskName,
			Usage: "Build and publish hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.HashreleasePush(cfg)
				tasks.HashreleaseCleanRemote(cfg)
			},
			Parallel: false,
		},
		Deps: []string{hashreleaseValidateTaskName, hashreleaseBuildTaskName},
	}
}

func HashreleaseGarbageCollect(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseGarbageCollectTaskName,
			Usage: "Clean up older hashreleases",
			Action: func(a *goyekv2.A) {
				tasks.HashreleaseCleanRemote(cfg)
			},
			Parallel: false,
		},
	}
}
