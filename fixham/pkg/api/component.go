package api

import (
	"os"

	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"
	"github.com/kelseyhightower/envconfig"

	"github.com/projectcalico/fixham/internal/docker"
	"github.com/projectcalico/fixham/pkg/config"
)

// Component is a struct that represents a component of the project.
type Component struct {
	name        string
	packageName string
	tasks       []*goyek.DefinedTask
}

// NewComponent returns a new Component
func NewComponent(name string, packageName string) *Component {
	return &Component{
		name:        name,
		packageName: packageName,
		tasks:       []*goyek.DefinedTask{},
	}
}

// Path returns the path used for the component
func (c *Component) Path() string {
	currentDir, _ := os.Getwd()
	return currentDir
}

// Name returns the name of the component
func (c *Component) Name() string {
	return c.name
}

// PackageName returns the package name of the component
func (c *Component) PackageName() string {
	return c.packageName
}

// Config returns the configuration of the component
func (c *Component) Config() *config.Config {
	cfg := config.Config{}
	cfg.SetPackageName(c.PackageName())
	envconfig.MustProcess("", &cfg)
	return &cfg
}

// DockerRunner returns a DockerRunner to be used in the component
func (c *Component) DockerRunner() *docker.DockerRunner {
	runner := docker.MustDockerRunner()
	return runner
}

// DockerGoBuildRunner returns a GoBuildRunner to be used in the component
func (c *Component) DockerGoBuildRunner() *docker.GoBuildRunner {
	runner := docker.MustGoBuildRunner(c.Config().GoBuildVersion, c.packageName, c.Path())
	return runner
}

// AddTask adds a task to the component
func (c *Component) AddTask(task ...*goyek.DefinedTask) {
	c.tasks = append(c.tasks, task...)
}

// Tasks returns the tasks for the component
func (c *Component) Tasks() []*goyek.DefinedTask {
	return c.tasks
}

// Register registers the component
func (c *Component) Register() {
	c.Tasks()
	boot.Main()
}
