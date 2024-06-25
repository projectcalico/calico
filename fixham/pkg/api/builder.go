package api

import (
	"flag"
	"os"

	"github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/internal/config"
	"github.com/projectcalico/fixham/internal/docker"
)

var debug bool

// Builder is a struct that represents a component of the project.
type Builder struct {
	name        string
	packageName string
	tasks       map[string]*goyek.DefinedTask
}

// NewBuilder returns a new Component
func NewBuilder(name string, packageName string) *Builder {
	return &Builder{
		name:        name,
		packageName: packageName,
		tasks:       make(map[string]*goyek.DefinedTask),
	}
}

// Path returns the path used for the component
func (c *Builder) Path() string {
	currentDir, _ := os.Getwd()
	return currentDir
}

// Name returns the name of the component
func (c *Builder) Name() string {
	return c.name
}

// PackageName returns the package name of the component
func (c *Builder) PackageName() string {
	return c.packageName
}

// Config returns the configuration of the component
func (c *Builder) Config() *config.Config {
	cfg := config.NewConfig(c.packageName)
	envconfig.MustProcess("", cfg)
	return cfg
}

// DockerRunner returns a DockerRunner to be used in the component
func (c *Builder) DockerRunner() *docker.DockerRunner {
	runner := docker.MustDockerRunner()
	return runner
}

// DockerGoBuildRunner returns a GoBuildRunner to be used in the component
func (c *Builder) DockerGoBuildRunner() *docker.GoBuildRunner {
	runner := docker.MustGoBuildRunner(c.Config().GoBuildVersion, c.packageName, c.Path())
	if c.Config().GoBuildImageName != "" {
		runner = runner.WithGoBuildImageName(c.Config().GoBuildImageName)
	}
	return runner
}

// AddTask adds a task to the component
func (c *Builder) AddTask(task ...*goyek.DefinedTask) {
	for _, t := range task {
		c.tasks[t.Name()] = t
	}
}

// GetTask returns a task defined in the component
func (c *Builder) GetTask(name string) *goyek.DefinedTask {
	return c.tasks[name]
}

// Tasks returns the tasks for the component
func (c *Builder) Tasks() []*goyek.DefinedTask {
	tasks := make([]*goyek.DefinedTask, 0, len(c.tasks))
	for _, t := range c.tasks {
		tasks = append(tasks, t)
	}
	return tasks
}

// setDefaultTask adds the default task to the component
func (c *Builder) setDefaultTask(task *goyek.DefinedTask) {
	if task == nil {
		logrus.Fatal("default task is required")
	}
	c.AddTask(goyek.Define(goyek.Task{
		Name:     "default",
		Usage:    "Default task. This is run when no task is specified",
		Deps:     goyek.Deps{task},
		Parallel: false,
	}))
	goyek.SetDefault(task)
}

// Register registers the component
func (c *Builder) Register(defaultTask *goyek.DefinedTask) {
	c.init()
	c.setDefaultTask(defaultTask)
	c.Tasks()
	boot.Main()
}

func (c *Builder) init() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
}
