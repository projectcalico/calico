package operator

import (
	"os"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	operatorRepo = "git@github.com:tigera/operator.git"
)

func operatorDir(outDir string) string {
	return outDir + "/operator"
}

func Clone(dir, branchName string) error {
	clonePath := operatorDir(dir)
	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		_, err := command.GitInDir(clonePath, "checkout", branchName)
		if err == nil {
			_, err = command.GitInDir(clonePath, "pull")
			return err
		}
	}
	_, err := command.GitInDir(dir, "clone", operatorRepo, "--branch", branchName)
	return err
}

func GitVersion(repoRootDir string) (string, error) {
	return command.GitVersion(operatorDir(repoRootDir), false)
}

func GitVersionDirty(repoRootDir string) (string, error) {
	return command.GitVersion(operatorDir(repoRootDir), true)
}

func GitBranch(repoRootDir string) (string, error) {
	return command.GitInDir(operatorDir(repoRootDir), "rev-parse", "--abbrev-ref", "HEAD")
}
