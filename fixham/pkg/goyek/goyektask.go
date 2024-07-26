package goyek

import "github.com/goyek/goyek/v2"

// GoyekTask represents a Goyek task.
// It is a wrapper around goyek.Task
// that overrides the Desp to be a string list of task names
type GoyekTask struct {
	goyek.Task
	Deps []string
}
