package api

import (
	goyekv2 "github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/goyek"
)

// Builder is a struct that represents a component of the project.
type Builder struct {
	config *config.Config
	tasks  map[string]*goyek.GoyekTask
}

// NewBuilder returns a new Builder
func NewBuilder() *Builder {
	return &Builder{
		config: config.LoadConfig(),
		tasks:  make(map[string]*goyek.GoyekTask),
	}
}

// Config returns the configuration of the component
func (c *Builder) Config() *config.Config {
	return c.config
}

// DockerRunner returns a DockerRunner to be used in the component
func (c *Builder) DockerRunner() *registry.DockerRunner {
	runner := registry.MustDockerRunner()
	return runner
}

// AddTask adds a task to the component
func (c *Builder) AddTask(task ...*goyek.GoyekTask) {
	for _, t := range task {
		c.tasks[t.Name] = t
	}
}

// Tasks returns the tasks for the component
func (c *Builder) Tasks() map[string]*goyek.GoyekTask {
	return c.tasks
}

// Register registers the tasks for the component
func (c *Builder) Register() {
	definedTaskMap := make(map[string]*goyekv2.DefinedTask, 0)
	for name, task := range c.Tasks() {
		definedTaskMap[name] = goyekv2.Define(task.Task)
	}
	for name, task := range c.Tasks() {
		if len(task.Deps) > 0 {
			deps := goyekv2.Deps{}
			for _, dep := range task.Deps {
				deps = append(deps, definedTaskMap[dep])
			}
			definedTaskMap[name].SetDeps(deps)
		}
	}
	boot.Main()
}
