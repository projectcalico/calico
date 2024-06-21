package client

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/internal/docker"
)

type Client struct {
	packageName   string
	goBuildRunner *docker.GoBuildRunner
}

func NewClient(packageName string) *Client {
	return &Client{
		packageName:   packageName,
		goBuildRunner: docker.NewGoBuildRunner(packageName),
	}
}

func (c *Client) WithGoBuildVersion(version string) *Client {
	c.goBuildRunner.WithVersion(version)
	return c
}

func (c *Client) Lint(args ...string) {
	gitConfigSSH := ""
	if os.Getenv("GIT_USE_SSH") == "true" {
		gitConfigSSH = "git config --global url.\"ssh://git@github.com/\".insteadOf \"https://github.com/\";"
	}
	if len(args) == 0 {
		args = []string{"--max-issues-per-linter 0", "--max-same-issues 0", "--timeout 8m"}
	}
	logrus.Info("Running linter with args: ", args)
	cmd := fmt.Sprintf("%s golangci-lint run %s", gitConfigSSH, strings.Join(args, " "))
	c.goBuildRunner.WithShCmd(cmd).Run()
}

func (c *Client) CheckFmt() {
	cmd := fmt.Sprintf("exec 5>&1; ! [[ `find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -l -local %s | tee >(cat >&5)` ]]", c.packageName)
	c.goBuildRunner.WithBashCmd(cmd).Run()
}

func (c *Client) FixFmt() {
	cmd := fmt.Sprintf("find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -w -local %s", c.packageName)
	c.goBuildRunner.WithShCmd(cmd).Run()
}
