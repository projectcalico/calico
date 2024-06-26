package goyek

import (
	"github.com/goyek/goyek/v2"
	"github.com/projectcalico/fixham/pkg/tasks"
)

func Clean(paths []string, images []string) *GoyekTask {
	return &GoyekTask{
		Task: goyek.Task{
			Name:  "clean",
			Usage: "Clean project",
			Action: func(a *goyek.A) {
				tasks.Clean(paths, images)
			},
			Parallel: false,
		},
	}
}
