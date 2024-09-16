package operator

import (
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

// Clone clones the operator repo into a path from the repoRootDir.
func Clone(cfg Config) error {
	targetDir := cfg.Dir
	clonePath := filepath.Dir(targetDir)
	if err := os.MkdirAll(clonePath, utils.DirPerms); err != nil {
		return err
	}
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		_, err := command.GitInDir(targetDir, "checkout", cfg.Branch)
		if err == nil {
			_, err = command.GitInDir(targetDir, "pull")
			return err
		}
	}
	_, err := command.GitInDir(clonePath, "clone", cfg.Repo, "--branch", cfg.Branch)
	return err
}

// GitVersion returns the git version of the operator repo.
func GitVersion(operatorDir string) (string, error) {
	return command.GitVersion(operatorDir, false)
}

// GitBranch returns the git branch of the operator repo.
func GitBranch(operatorDir string) (string, error) {
	return command.GitInDir(operatorDir, "rev-parse", "--abbrev-ref", "HEAD")
}
