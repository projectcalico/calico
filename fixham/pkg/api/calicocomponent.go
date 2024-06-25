package api

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	calicoPackageName = "github.com/projectcalico/calico"
)

// CalicoComponent is a component in the Calico project
type CalicoComponent struct {
	Component
}

// NewCalicoComponent returns a new CalicoComponent
func NewCalicoComponent(name string) *CalicoComponent {
	return &CalicoComponent{
		Component: *NewComponent(name, calicoPackageName),
	}
}

// Path returns the path used for Calico component
func (c *CalicoComponent) Path() string {
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
