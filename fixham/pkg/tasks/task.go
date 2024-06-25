package tasks

import "github.com/goyek/goyek/v2"

func RegisterTask(task goyek.Task) *goyek.DefinedTask {
	return goyek.Define(task)
}
