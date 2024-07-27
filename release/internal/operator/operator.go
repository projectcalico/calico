package operator

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	ImageName = "tigera/operator"
)

// GenVersions generates the versions for operator.
func GenVersions(repoRootDir, componentsVersionPath string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("OS_VERSIONS=%s", componentsVersionPath))
	env = append(env, fmt.Sprintf("COMMON_VERSIONS=%s", componentsVersionPath))
	if _, err := command.MakeInDir(operatorDir(repoRootDir), []string{"gen-versions"}, env); err != nil {
		return err
	}
	return nil
}

// ImageAll build all the images for operator .
func ImageAll(archs []string, version, repoRootDir string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(archs, " ")))
	env = append(env, fmt.Sprintf("VERSION=%s", version))
	if _, err := command.MakeInDir(operatorDir(repoRootDir), []string{"image-all"}, env); err != nil {
		return err
	}
	return nil
}

// InitImage build the init image for operator.
func InitImage(version, repoRootDir string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("VERSION=%s", version))
	if _, err := command.MakeInDir(operatorDir(repoRootDir), []string{"image-init"}, env); err != nil {
		return err
	}
	return nil
}
