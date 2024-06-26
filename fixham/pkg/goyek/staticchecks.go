package goyek

import (
	"github.com/goyek/goyek/v2"
	"github.com/projectcalico/fixham/internal/config"
	"github.com/projectcalico/fixham/internal/docker"
	"github.com/projectcalico/fixham/pkg/tasks"
)

func Lint(runner *docker.GoBuildRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyek.Task{
			Name:  "lint",
			Usage: "Run linters",
			Action: func(a *goyek.A) {
				tasks.Lint(runner, cfg)
			},
			Parallel: true,
		},
	}
}

func CheckFmt(runner *docker.GoBuildRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyek.Task{
			Name:  "check-fmt",
			Usage: "Check code formatting",
			Action: func(a *goyek.A) {
				tasks.CheckFmt(runner, cfg)
			},
			Parallel: true,
		},
	}
}

func FixFmt(runner *docker.GoBuildRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyek.Task{
			Name:  "fix-fmt",
			Usage: "Fix code formatting",
			Action: func(a *goyek.A) {
				tasks.FixFmt(runner, cfg)
			},
			Parallel: true,
		},
	}
}

func StaticChecks(runner *docker.GoBuildRunner, cfg *config.Config) *GoyekTask {
	return &GoyekTask{
		Task: goyek.Task{
			Name:     "static-checks",
			Usage:    "Run static checks",
			Parallel: true,
		},
		Deps: []string{"lint", "check-fmt"},
	}
}
