package tasks

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// CleanFiles removes the files at the given paths.
// If a path contains a wildcard, it will be expanded.
// If a path is a directory, it will be removed recursively.
// If a path is a file, it will be removed.
func CleanFiles(paths ...string) {
	for _, p := range paths {
		err := os.RemoveAll(p)
		if err != nil {
			logrus.WithField("path", p).WithError(err).Fatal("removing file(s) failed")
		}
	}
}

// ResetRepo resets the git repo at the given directory.
func ResetRepo(dir string) {
	_, err := command.GitInDir(dir, "checkout", "HEAD")
	if err != nil {
		logrus.WithError(err).Fatal("failed to reset repo")
	}
}
