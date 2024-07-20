package api

import (
	goyekv2 "github.com/goyek/goyek/v2"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/docker"
	"github.com/projectcalico/calico/fixham/pkg/goyek"
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

// Path returns the path used for the component
func (c *Builder) Path() string {
	return c.config.RepoRootDir
}

func (c *Builder) Output() string {
	return c.config.RepoRootDir + "/fixham/output"
}

// Name returns the name of the component
func (c *Builder) Name() string {
	return c.config.Name
}

// PackageName returns the package name of the component
func (c *Builder) PackageName() string {
	return c.config.PackageName
}

// Config returns the configuration of the component
func (c *Builder) Config() *config.Config {
	return c.config
}

// DockerRunner returns a DockerRunner to be used in the component
func (c *Builder) DockerRunner() *docker.DockerRunner {
	runner := docker.MustDockerRunner()
	return runner
}

// DockerGoBuildRunner returns a GoBuildRunner to be used in the component
func (c *Builder) DockerGoBuildRunner() *docker.GoBuildRunner {
	return docker.MustGoBuildRunner(c.config.GoBuildImageName, c.Config().GoBuildVersion, c.PackageName(), c.Path(), c.config.RepoRootDir)
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

// Register
func (c *Builder) Register() {
	definedTaskMap := make(map[string]*goyekv2.DefinedTask, len(c.Tasks()))
	for name, task := range c.Tasks() {
		definedTaskMap[name] = goyekv2.Define(task.Task)
	}
	for _, task := range c.Tasks() {
		if task.Deps != nil {
			deps := goyekv2.Deps{}
			for _, dep := range task.Deps {
				deps = append(deps, definedTaskMap[dep])
			}
			definedTaskMap[task.Name].SetDeps(deps)
		}
	}
}
