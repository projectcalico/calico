package api

import (
	"os"

	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"
	"github.com/kelseyhightower/envconfig"

	"github.com/projectcalico/fixham/internal/docker"
	"github.com/projectcalico/fixham/pkg/config"
)

type Component struct {
	name        string
	packageName string
	tasks       []*goyek.DefinedTask
}

func NewComponent(name string, packageName string) *Component {
	return &Component{
		name:        name,
		packageName: packageName,
		tasks:       []*goyek.DefinedTask{},
	}
}

func (c *Component) Path() string {
	currentDir, _ := os.Getwd()
	return currentDir
}

func (c *Component) Name() string {
	return c.name
}

func (c *Component) PackageName() string {
	return c.packageName
}

func (c *Component) Config() *config.Config {
	cfg := config.Config{}
	cfg.SetPackageName(c.PackageName())
	envconfig.MustProcess("", &cfg)
	return &cfg
}

func (c *Component) DockerRunner() *docker.DockerRunner {
	runner := docker.MustDockerRunner()
	return runner
}

func (c *Component) DockerGoBuildRunner() *docker.GoBuildRunner {
	runner := docker.MustGoBuildRunner(c.Config().GoBuildVersion, c.packageName, c.Path())
	return runner
}

func (c *Component) AddTask(task ...*goyek.DefinedTask) {
	c.tasks = append(c.tasks, task...)
}

func (c *Component) Tasks() []*goyek.DefinedTask {
	return c.tasks
}

func (c *Component) Register() {
	c.Tasks()
	boot.Main()
}
