package operator

import (
	"os"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	operatorRepo = "git@github.com:tigera/operator.git"
)

func operatorDir(repoRootDir string) string {
	return repoRootDir + "/operator"
}

func Clone(repoRootDir, branchName string) error {
	clonePath := operatorDir(repoRootDir)
	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		_, err := command.GitInDir(clonePath, "checkout", branchName)
		if err == nil {
			_, err = command.GitInDir(clonePath, "pull")
			return err
		}
	}
	_, err := command.GitInDir(repoRootDir, "clone", operatorRepo, "--branch", branchName)
	return err
}

func GitVersion(repoRootDir, devTagSuffix string) (string, error) {
	// if devTagSuffix != "" {
	// 	return git.GitVersionDev(operatorDir(repoRootDir), devTagSuffix, false)
	// }
	return command.GitVersion(operatorDir(repoRootDir), false)
}

func GitVersionDirty(repoRootDir, devTagSuffix string) (string, error) {
	// if devTagSuffix != "" {
	// 	return command.GitVersionDev(operatorDir(repoRootDir), devTagSuffix, true)
	// }
	return command.GitVersion(operatorDir(repoRootDir), true)
}

func GitBranch(repoRootDir string) (string, error) {
	return command.GitInDir(operatorDir(repoRootDir), "rev-parse", "--abbrev-ref", "HEAD")
}
