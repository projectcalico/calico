package tasks

import (
	"fmt"

	"github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/internal/config"
	"github.com/projectcalico/fixham/internal/docker"
)

func lintTask(runner *docker.GoBuildRunner, cfg *config.Config) goyek.Task {
	return goyek.Task{
		Name:  "lint",
		Usage: "Run linter",
		Action: func(a *goyek.A) {
			cmd := "golangci-lint run " + cfg.LintArgs
			if cfg.GitUseSSH {
				cmd = "git config --global url.\"ssh://git@github.com/\".insteadOf \"https://github.com/\"; " + cmd
			}
			err := runner.RunShCmd(cmd)
			if err != nil {
				logrus.WithError(err).Fatal("Component has lint errors")
			}
		},
		Parallel: true,
	}
}

func checkFmtTask(runner *docker.GoBuildRunner, cfg *config.Config) goyek.Task {
	return goyek.Task{
		Name:  "check-fmt",
		Usage: "Check code formatting",
		Action: func(a *goyek.A) {
			logrus.Info("Checking code formatting.  Any listed files don't match goimports:")
			cmd := fmt.Sprintf("exec 5>&1; ! [[ `find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -l -local %s | tee >(cat >&5)` ]]", cfg.PackageName())
			err := runner.RunBashCmd(cmd)
			if err != nil {
				logrus.WithError(err).Fatal("Code formatting check failed.  Run `fix-fmt` to fix formatting.")
			}
		},
		Parallel: true,
	}
}

func fixFmtTask(runner *docker.GoBuildRunner, cfg *config.Config) goyek.Task {
	return goyek.Task{
		Name:  "fix-fmt",
		Usage: "Fix code formatting",
		Action: func(a *goyek.A) {
			cmd := "find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -w -local " + cfg.PackageName()
			err := runner.RunBashCmd(cmd)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to fix formatting")
			}
		},
	}
}

func DefineStaticChecksTasks(runner *docker.GoBuildRunner, cfg *config.Config) []*goyek.DefinedTask {
	lint := RegisterTask(lintTask(runner, cfg))
	checkFmt := RegisterTask(checkFmtTask(runner, cfg))
	fixFmt := RegisterTask(fixFmtTask(runner, cfg))
	staticChecks := RegisterTask(goyek.Task{
		Name:  "static-checks",
		Usage: "Run linter and check formatting",
		Deps:  goyek.Deps{lint, checkFmt},
	})
	return []*goyek.DefinedTask{staticChecks, lint, checkFmt, fixFmt}
}
