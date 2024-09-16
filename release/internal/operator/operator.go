package operator

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
)

type Config struct {
	// Repo is the repository for the operator
	Repo string `envconfig:"OPERATOR_REPO" default:"git@github.com:tigera/operator.git"`

	// Branch is the repository for the operator
	Branch string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// Dir is the directory to clone the operator repository
	Dir string `envconfig:"OPERATOR_DIR"`

	// Image is the image for Tigera operator
	Image string `envconfig:"OPERATOR_IMAGE" default:"tigera/operator"`

	// Registry is the registry for Tigera operator
	Registry string `envconfig:"OPERATOR_REGISTRY" default:"quay.io"`
}

func (c Config) String() string {
	return fmt.Sprintf("Repo: %s, Branch: %s, Image: %s, Registry: %s", c.Repo, c.Branch, c.Image, c.Registry)
}

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
