package operator

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
)

const (
	ImageName = "tigera/operator"
	Registry  = registry.QuayRegistry
)

// GenVersions generates the versions for operator.
func GenVersions(componentsVersionPath, dir string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("OS_VERSIONS=%s", componentsVersionPath))
	env = append(env, fmt.Sprintf("COMMON_VERSIONS=%s", componentsVersionPath))
	if _, err := command.MakeInDir(dir, []string{"gen-versions"}, env); err != nil {
		return err
	}
	return nil
}

// ImageAll build all the images for operator .
func ImageAll(archs []string, version, operatorDir string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(archs, " ")))
	env = append(env, fmt.Sprintf("VERSION=%s", version))
	if _, err := command.MakeInDir(operatorDir, []string{"image-all"}, env); err != nil {
		return err
	}
	return nil
}

// InitImage build the init image for operator.
func InitImage(version, operatorDir string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("VERSION=%s", version))
	if _, err := command.MakeInDir(operatorDir, []string{"image-init"}, env); err != nil {
		return err
	}
	return nil
}
