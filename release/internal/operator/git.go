package operator

import (
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	operatorRepo = "git@github.com:tigera/operator.git"
)

func Dir(dir string) string {
	return filepath.Join(dir, "operator")
}

// Clone clones the operator repo into a path from the repoRootDir.
func Clone(operatorDir, branchName string) error {
	clonePath := filepath.Dir(operatorDir)
	if err := os.MkdirAll(clonePath, utils.DirPerms); err != nil {
		return err
	}
	if _, err := os.Stat(operatorDir); !os.IsNotExist(err) {
		_, err := command.GitInDir(operatorDir, "checkout", branchName)
		if err == nil {
			_, err = command.GitInDir(operatorDir, "pull")
			return err
		}
	}
	_, err := command.GitInDir(clonePath, "clone", operatorRepo, "--branch", branchName)
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
