package goyek

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

const (
	pinnedVersionTaskName             = "hashrelease/pinned-version"
	hashreleaseTaskName               = "hashrelease"
	hashreleaseGarbageCollectTaskName = "hashrelease/garbage-collect"
)

// PinVersion creates a Goyek task for generating a pinned version file.
// This is used by hashreleases for tracking the versions of the components.
func PinnedVersion(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  pinnedVersionTaskName,
			Usage: "Generate pinned version file",
			Action: func(a *goyekv2.A) {
				if !cfg.IsHashrelease {
					logrus.Fatal("This task is only valid for hashreleases")
				}
				tasks.PinnedVersion(cfg)
			},
			Parallel: false,
		},
		Deps: []string{preReleaseTask},
	}
}

// Hashrelease creates a Goyek task for building and publishing a hashrelease.
func Hashrelease(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseTaskName,
			Usage: "Build and publish hashrelease",
			Action: func(a *goyekv2.A) {
				if !cfg.IsHashrelease {
					logrus.Fatal("This task is only valid for hashreleases. Ensure you have set IS_HASHRELEASE=true in your environment")
				}
				tasks.HashreleasePush(cfg)
				tasks.HashreleaseCleanRemote(cfg)
			},
			Parallel: false,
		},
		Deps: []string{prePublishTask, buildTaskName},
	}
}

// HashreleaseGarbageCollect creates a Goyek task for cleaning up older hashreleases.
func HashreleaseGarbageCollect(cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyekv2.Task{
			Name:  hashreleaseGarbageCollectTaskName,
			Usage: "Clean up older hashreleases",
			Action: func(a *goyekv2.A) {
				if !cfg.IsHashrelease {
					logrus.Fatal("This task is only valid for hashreleases. Ensure you have set IS_HASHRELEASE=true in your environment")
				}
				tasks.HashreleaseCleanRemote(cfg)
			},
			Parallel: false,
		},
	}
}
