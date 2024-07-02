package tasks

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/docker"
)

func Lint(runner *docker.GoBuildRunner, cfg *config.Config) {
	cmd := "golangci-lint run " + cfg.LintArgs
	if cfg.GitUseSSH {
		cmd = "git config --global url.\"ssh://git@github.com/\".insteadOf \"https://github.com/\"; " + cmd
	}
	err := runner.RunShCmd(cmd)
	if err != nil {
		logrus.WithError(err).Fatalf("%s has linting errors", cfg.Name)
	}
}

func CheckFmt(runner *docker.GoBuildRunner, cfg *config.Config) {
	logrus.Info("Checking code formatting.  Any listed files don't match goimports:")
	cmd := fmt.Sprintf("exec 5>&1; ! [[ `find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -l -local %s | tee >(cat >&5)` ]]", cfg.PackageName)
	err := runner.RunBashCmd(cmd)
	if err != nil {
		logrus.WithError(err).Fatal("Code formatting check failed.  Run `fix-fmt` to fix formatting.")
	}
}

func FixFmt(runner *docker.GoBuildRunner, cfg *config.Config) {
	cmd := "find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -w -local " + cfg.PackageName
	err := runner.RunBashCmd(cmd)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to fix formatting")
	}
}
