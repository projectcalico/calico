package api

import (
	"os"

	"github.com/goyek/x/boot"
	"github.com/kelseyhightower/envconfig"

	"github.com/projectcalico/fixham/internal/docker"
	"github.com/projectcalico/fixham/pkg/config"
)

type Component struct {
	name        string
	packageName string
}

func NewComponent(name string, packageName string) *Component {
	return &Component{
		name:        name,
		packageName: packageName,
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

func (c *Component) Tasks() {
}

func (c *Component) Register() {
	var p Package = c
	p.Tasks()
	boot.Main()
}
