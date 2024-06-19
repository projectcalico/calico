package client

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/ctl/docker"
)

const (
	goBuildImageName = "calico/go-build"
	goBuildVersion   = "v0.91"
)

type GoBuild struct {
	Name    string
	Version string
}

func (g GoBuild) Image() string {
	name := g.Name
	if name == "" {
		name = goBuildImageName
	}
	version := g.Version
	if version == "" {
		version = goBuildVersion
	}
	return name + ":" + version
}

type Client struct {
	PackageName string
	GoBuild     GoBuild
}

func (c *Client) GoBuildImage() string {
	return c.GoBuild.Image()
}

func (c *Client) DockerGoBuild(cmd string) {
	docker.DockerGoBuild(c.GoBuildImage(), cmd, c.PackageName)
}

func (c *Client) Lint(args string) {
	gitConfigSSH := ""
	if os.Getenv("GIT_USE_SSH") == "true" {
		gitConfigSSH = "git config --global url.\"ssh://git@github.com/\".insteadOf \"https://github.com/\";"
	}
	if args == "" {
		args = "--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"
	}
	logrus.Info("Running linter with args: ", args)
	docker.DockerGoBuild(c.GoBuildImage(), fmt.Sprintf("%s golangci-lint run %s", gitConfigSSH, args), c.PackageName)
}

func (c *Client) CheckFmt() {
	c.DockerGoBuild(fmt.Sprintf("exec 5>&1; ! [[ `find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -l -local %s | tee >(cat >&5)` ]]", c.PackageName))
}

func (c *Client) FixFmt() {
	c.DockerGoBuild(fmt.Sprintf("find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -w -local %s", c.PackageName))
}
