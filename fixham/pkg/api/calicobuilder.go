package api

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"

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
	repoRootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	var out bytes.Buffer
	repoRootCmd.Stdout = &out
	err := repoRootCmd.Run()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get repo root")
		return ""
	}
	return strings.TrimSpace(out.String())
}

func (c *CalicoBuilder) Register() {
	c.AddTask(tasks.DefineStaticChecksTasks(c.DockerGoBuildRunner(), c.Config())...)
	c.Builder.Register()
}
