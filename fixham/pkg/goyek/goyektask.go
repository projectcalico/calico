package goyek

import "github.com/goyek/goyek/v2"

type GoyekTask struct {
	goyek.Task
	Deps []string
}
