package bootstrap

import (
	"github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"
)

// TestType represents the type of test to run.
type TestType int

const (
	Unit TestType = iota
	Functional
	System
)

// String returns the string representation of the test type.
func (t TestType) String() string {
	switch t {
	case Unit:
		return "ut"
	case Functional:
		return "fv"
	case System:
		return "st"
	default:
		logrus.WithField("testType", t).Fatal("Unknown test type")
		return ""
	}
}

// Description returns the description of the test type.
func (t TestType) Description() string {
	switch t {
	case Unit:
		return "unit tests"
	case Functional:
		return "functional tests"
	case System:
		return "system tests"
	default:
		logrus.WithField("testType", t).Fatal("Unknown test type")
		return ""
	}
}

// definedTestTask is a wrapper around goyek.DefinedTask that includes the test type.
type definedTestTask struct {
	goyek.DefinedTask
	TestType
}

type definedTestTasks map[TestType]*goyek.DefinedTask

func (t definedTestTasks) set(testType TestType, task *goyek.DefinedTask) {
	t[testType] = task
}

func (t definedTestTasks) values() []*goyek.DefinedTask {
	values := make([]*goyek.DefinedTask, 0, len(t))
	for _, v := range t {
		values = append(values, v)
	}
	return values
}

var tests = &definedTestTasks{}

// defineTestTask defines a test tast of the given type.
//
// This is a helper function to avoid code duplication in DefineUt, DefineFv, and DefineSt.
// Once a test task is defined, it is added to the tests map and the Test task is updated with the new dependencies.
func defineTestTask(testType TestType, action func(a *goyek.A), deps goyek.Deps, parallel bool) *goyek.DefinedTask {
	definedTask := *goyek.Define(goyek.Task{
		Name:     testType.String(),
		Usage:    "Run " + testType.Description(),
		Action:   action,
		Deps:     deps,
		Parallel: parallel,
	})
	task := &definedTestTask{
		TestType:    testType,
		DefinedTask: definedTask,
	}
	tests.set(testType, &task.DefinedTask)
	Test.SetDeps(tests.values())
	return &definedTask
}

// DefineUt defines a unit test task.
func DefineUt(action func(a *goyek.A), deps goyek.Deps, parallel bool) *goyek.DefinedTask {
	return defineTestTask(Unit, action, deps, parallel)
}

// DefineFv defines a functional test task.
func DefineFv(action func(a *goyek.A), deps goyek.Deps, parallel bool) *goyek.DefinedTask {
	return defineTestTask(Functional, action, deps, parallel)
}

// DefineSt defines a system test task.
func DefineSt(action func(a *goyek.A), deps goyek.Deps, parallel bool) *goyek.DefinedTask {
	return defineTestTask(System, action, deps, parallel)
}

// Test is the default test task.
var Test = goyek.Define(goyek.Task{
	Name:  "test",
	Usage: "Run tests",
})
