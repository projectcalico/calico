package utils

import (
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	// DefaultBranch is the default branch of the repository.
	DefaultBranch = "master"
)

// GitBranch returns the current git branch of the repository.
func GitBranch(dir string) (string, error) {
	return command.GitInDir(dir, "rev-parse", "--abbrev-ref", "HEAD")
}

// GitVersion returns the current git version of the repository.
func GitVersion(dir string) (string, error) {
	return command.GitVersion(dir, false)
}

// GitIsDirty returns true if the repository is dirty.
func GitIsDirty(dir string) (bool, error) {
	version, err := command.GitVersion(dir, true)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(version, "-dirty"), nil
}
