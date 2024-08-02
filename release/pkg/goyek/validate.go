package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	prePublishTask = "pre-validate/publish"
	preReleaseTask = "pre-validate/start"
)

// PreReleaseValidate creates a Goyek task for validating a release before starting
func PreReleaseValidate(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  preReleaseTask,
			Usage: "Validate release before starting",
			Action: func(a *goyekv2.A) {
				tasks.PreReleaseValidate(cfg)
			},
			Parallel: false,
		},
	}
}

// PrePublishValidate creates a Goyek task for validating a release before publishing
func PrePublishValidate(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  prePublishTask,
			Usage: "Validate release before publishing",
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
