package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	operatorBuildTaskName   = "operator/build"
	operatorPublishTaskName = "operator/publish"
	operatorTaskName        = "operator"
)

func OperatorBuild(runner *registry.DockerRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  operatorBuildTaskName,
			Usage: "Build and tag operator",
			Action: func(a *goyekv2.A) {
				if cfg.IsHashrelease {
					tasks.PinnedVersion(cfg)
					tasks.OperatorHashreleaseBuild(runner, cfg)
				} else {
					logrus.Fatal("Not implemented")
				}
			},
			Parallel: false,
		},
	}
}

func OperatorPublish(runner *registry.DockerRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  operatorPublishTaskName,
			Usage: "Publish operator",
			Action: func(a *goyekv2.A) {
				if cfg.IsHashrelease {
					tasks.OperatorHashreleasePush(runner, cfg)
				} else {
					logrus.Fatal("Not implemented")
				}
			},
			Parallel: false,
		},
		Deps: []string{preReleaseTask, operatorBuildTaskName},
	}
}

func Operator(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:     operatorTaskName,
			Usage:    "Build & publish operator",
			Parallel: false,
			Action: func(a *goyekv2.A) {
				relType := "release"
				if cfg.IsHashrelease {
					relType = "hashrelease"
				}
				logrus.Infof("Operator %s built and publish complete", relType)
			},
		},
		Deps: []string{operatorBuildTaskName, operatorPublishTaskName},
	}
}
