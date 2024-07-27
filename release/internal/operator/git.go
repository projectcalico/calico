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

func operatorDir(repoRootDir string) string {
	return filepath.Join(repoRootDir, utils.ReleaseFolderName, "tmp", "operator")
}

// Clone clones the operator repo into a path from the repoRootDir.
func Clone(repoRootDir, branchName string) error {
	operatorDir := operatorDir(repoRootDir)
	clonePath := filepath.Dir(operatorDir)
	if err := os.MkdirAll(clonePath, 0755); err != nil {
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
func GitVersion(repoRootDir string) (string, error) {
	return command.GitVersion(operatorDir(repoRootDir), false)
}

// GitBranch returns the git branch of the operator repo.
func GitBranch(repoRootDir string) (string, error) {
	return command.GitInDir(operatorDir(repoRootDir), "rev-parse", "--abbrev-ref", "HEAD")
}
