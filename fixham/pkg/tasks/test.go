package tasks

import (
	"github.com/goyek/goyek/v2"
)

// TestType represents the type of test to run.
type TestType string

const (
	Unit       TestType = "unit"
	Functional TestType = "functional"
	System     TestType = "system"
)

// Description returns the description of the test type.
func (t TestType) Description() string {
	return string(t) + " tests"
}

type TestTask struct {
	TestType
	*goyek.Task
}

func NewTestTask(testType TestType, action func(a *goyek.A), deps goyek.Deps, parallel bool) *TestTask {
	return &TestTask{
		TestType: testType,
		Task: &goyek.Task{
			Name:     string(testType),
			Usage:    testType.Description(),
			Action:   action,
			Deps:     deps,
			Parallel: parallel,
		},
	}
}

func RegisterTestTask(task *TestTask) *goyek.DefinedTask {
	return RegisterTask(*task.Task)
}
