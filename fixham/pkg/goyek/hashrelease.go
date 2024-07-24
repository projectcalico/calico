package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/registry"
	"github.com/projectcalico/calico/fixham/pkg/tasks"
)

const (
	pinnedVersionTaskName             = "pinned-version"
	operatorBuildTaskName             = "operator/build"
	operatorPublishTaskName           = "operator/publish"
	operatorTaskName                  = "operator"
	hashreleaseBuildTaskName          = "build"
	hashreleaseValidateTaskName       = "validate"
	hashreleaseTaskName               = "publish"
	hashreleaseGarbageCollectTaskName = "garbage-collect"
	cleanTaskName                     = "clean"
)

func PinnedVersion(cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  pinnedVersionTaskName,
			Usage: "Generate pinned version file",
			Action: func(a *goyekv2.A) {
				tasks.PinnedVersion(cfg, outputDir)
			},
			Parallel: false,
		},
	}
}

func OperatorHashreleaseBuild(runner *registry.DockerRunner, cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  operatorBuildTaskName,
			Usage: "Build and tag operator hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.OperatorHashreleaseBuild(runner, cfg, outputDir)
			},
			Parallel: false,
		},
		Deps: []string{pinnedVersionTaskName},
	}
}

func OperatorHashreleasePublish(runner *registry.DockerRunner, cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  operatorPublishTaskName,
			Usage: "Publish operator hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.OperatorHashreleasePush(runner, cfg, outputDir)
			},
			Parallel: false,
		},
		Deps: []string{operatorBuildTaskName},
	}
}

func OperatorHashrelease(runner *registry.DockerRunner, cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:     operatorTaskName,
			Usage:    "Build & publish operator hashrelease",
			Parallel: false,
			Action: func(a *goyekv2.A) {
				logrus.Info("Operator hashrelease build and publish complete")
			},
		},
		Deps: []string{operatorBuildTaskName, operatorPublishTaskName},
	}
}

func HashreleaseBuild(cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseBuildTaskName,
			Usage: "Build hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.HashreleaseBuild(cfg, outputDir)
				tasks.HashreleaseNotes(cfg, outputDir)
				logrus.Info("Hashrelease build complete, run 'validate' to check the hashrelease.")
			},
			Parallel: false,
		},
		Deps: []string{operatorBuildTaskName},
	}
}

func HashreleaseValidate(cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseValidateTaskName,
			Usage: "Validate hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.HashreleaseValidate(cfg, outputDir)
			},
			Parallel: false,
		},
		Deps: []string{operatorPublishTaskName},
	}

}

func Hashrelease(cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseTaskName,
			Usage: "Build and publish hashrelease",
			Action: func(a *goyekv2.A) {
				tasks.HashreleasePush(cfg, outputDir)
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

func HashreleaseNotes(cfg *config.Config, outputDir string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  releaseNotesTaskName,
			Usage: "Generate release notes",
			Action: func(a *goyekv2.A) {
				tasks.HashreleaseNotes(cfg, outputDir)
			},
			Parallel: false,
		},
	}
}

func HashreleaseClean(outputPath string) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  cleanTaskName,
			Usage: "Clean up hashrelease artifacts",
			Action: func(a *goyekv2.A) {
				tasks.Clean([]string{outputPath}, nil)
			},
		},
	}
}
