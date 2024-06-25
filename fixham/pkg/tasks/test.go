package tasks

import (
	"github.com/goyek/goyek/v2"
)

// TestType represents the type of test to run.
type TestType string

const (
	Unit       TestType = "ut"
	Functional TestType = "fv"
	System     TestType = "st"
)

// Description returns the description of the test type.
func (t TestType) Description() string {
	var name string
	switch t {
	case Unit:
		name = "unit"
	case Functional:
		name = "functional"
	case System:
		return "system"
	default:
		return ""
	}
	return name + " tests"
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
			Usage:    "Run " + testType.Description(),
			Action:   action,
			Deps:     deps,
			Parallel: parallel,
		},
	}
}

func RegisterTestTask(task *TestTask) *goyek.DefinedTask {
	return RegisterTask(*task.Task)
}

func DefaultTestTask(deps goyek.Deps) *goyek.DefinedTask {
	return RegisterTask(goyek.Task{
		Name:     "test",
		Usage:    "Run all tests",
		Deps:     deps,
		Parallel: false,
	})
}
