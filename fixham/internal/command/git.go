package command

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func GitInDir(dir string, args ...string) (string, error) {
	return runner().RunInDir(dir, "git", args, nil)
}

func Git(args ...string) (string, error) {
	return runner().Run("git", args, nil)
}

func GitOrFailInDir(dir string, args ...string) {
	if _, err := GitInDir(dir, args...); err != nil {
		logrus.WithField("args", args).WithError(err).Fatal("Failed to run git command")
	}
}

func GitOrFail(args ...string) {
	if _, err := Git(args...); err != nil {
		logrus.WithField("args", args).WithError(err).Fatal("Failed to run git command")
	}
}

func GitVersion(dir string, includeDirty bool) (string, error) {
	args := []string{"describe", "--tags", "--always", "--long", "--abbrev=12"}
	if includeDirty {
		args = append(args, "--dirty")
	}
	return GitInDir(dir, args...)
}

func GitVersionDev(dir string, devTagSuffix string, includeDirty bool) (string, error) {
	args := []string{"describe", "--tags", "--match", fmt.Sprintf("'*%s*'", devTagSuffix), "--always", "--long", "--abbrev=12"}
	if includeDirty {
		args = append(args, "--dirty")
	}
	return GitInDir(dir, args...)
}
