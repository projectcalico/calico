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

type CalicoComponent struct {
	Component
}

func NewCalicoComponent(name string) *CalicoComponent {
	return &CalicoComponent{
		Component: *NewComponent(name, calicoPackageName),
	}
}

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
