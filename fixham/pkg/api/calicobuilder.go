package api

import (
	"github.com/projectcalico/fixham/pkg/tasks"
)

const (
	calicoPackageName = "github.com/projectcalico/calico"
)

// CalicoBuilder is a component in the Calico project
type CalicoBuilder struct {
	Builder
}

// NewCalicoBuilder returns a new CalicoComponent
func NewCalicoBuilder(name string) *CalicoBuilder {
	return &CalicoBuilder{
		Builder: *NewBuilder(name, calicoPackageName),
	}
}

// Path returns the path used for Calico component
func (c *CalicoBuilder) Path() string {
	return c.Config().RepoRootDir
}

func (c *CalicoBuilder) Register() {
	c.AddTask(tasks.DefineStaticChecksTasks(c.DockerGoBuildRunner(), c.Config())...)
	c.Builder.Register(c.GetTask("build"))
}
