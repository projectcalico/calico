package command

import (
	"github.com/sirupsen/logrus"
)

// GitInDir runs a git command in a specific directory.
func GitInDir(dir string, args ...string) (string, error) {
	return runner().RunInDir(dir, "git", args, nil)
}

// GitInDir runs a git command in a specific directory
// and fails if the command fails.
func GitInDirOrFail(dir string, args ...string) {
	if _, err := GitInDir(dir, args...); err != nil {
		logrus.WithError(err).Fatal("Failed to run git command")
	}
}

// Git runs a git command.
func Git(args ...string) (string, error) {
	return runner().Run("git", args, nil)
}

func GitVersion(dir string, includeDirty bool) (string, error) {
	args := []string{"describe", "--tags", "--always", "--long", "--abbrev=12"}
	if includeDirty {
		args = append(args, "--dirty")
	}
	return GitInDir(dir, args...)
}

// GitDir returns the root directory of the git repository.
func GitDir(repoDir string) (string, error) {
	args := []string{"rev-parse", "--show-toplevel"}
	if repoDir != "" {
		return GitInDir(repoDir, args...)
	}
	return Git(args...)
}
