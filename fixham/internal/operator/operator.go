package operator

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	ImageName = "tigera/operator"
)

func GenVersions(rootDir, componentsVersionPath string) error {
	env := os.Environ()
	env = append(env, "OS_VERSIONS="+componentsVersionPath)
	env = append(env, "COMMON_VERSIONS="+componentsVersionPath)
	if _, err := command.MakeInDir(operatorDir(rootDir), []string{"gen-versions"}, env); err != nil {
		return err
	}
	return nil
}

func ImageAll(archs []string, version string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=\"%s\"", strings.Join(archs, " ")))
	env = append(env, "VERSION="+version)
	if _, err := command.Make([]string{"image-all"}, env); err != nil {
		return err
	}
	return nil
}

func InitImage(version string) error {
	env := os.Environ()
	env = append(env, "VERSION="+version)
	if _, err := command.Make([]string{"image-init"}, env); err != nil {
		return err
	}
	return nil
}
