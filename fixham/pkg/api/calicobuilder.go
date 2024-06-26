package api

import "github.com/projectcalico/fixham/pkg/goyek"

// CalicoBuilder is a component in the Calico project
type CalicoBuilder struct {
	Builder
}

// NewCalicoBuilder returns a new CalicoComponent
func NewCalicoBuilder() *CalicoBuilder {
	return &CalicoBuilder{
		Builder: *NewBuilder(),
	}
}

// Path returns the path used for Calico component
func (c *CalicoBuilder) Path() string {
	return c.Config().RepoRootDir
}

func (f *CalicoBuilder) Tasks() map[string]*goyek.GoyekTask {
	f.AddTask(goyek.Lint(f.DockerGoBuildRunner(), f.Config()),
		goyek.CheckFmt(f.DockerGoBuildRunner(), f.Config()),
		goyek.FixFmt(f.DockerGoBuildRunner(), f.Config()),
		goyek.StaticChecks(f.DockerGoBuildRunner(), f.Config()))
	tasks := f.Builder.Tasks()
	return tasks
}
