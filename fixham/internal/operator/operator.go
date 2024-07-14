package operator

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	ImageName = "tigera/operator"
)

func GenVersion(rootDir, componentsVersionPath string) error {
	if _, err := command.MakeInDir(operatorDir(rootDir), []string{"gen-versions"},
		[]string{"OS_VERSIONS=" + componentsVersionPath, "COMMON_VERSIONS=" + componentsVersionPath}); err != nil {
		return err
	}
	return nil
}

func ImageAll(archs []string, version string) error {
	if _, err := command.Make([]string{"image-all"}, []string{fmt.Sprintf("ARCHES=\"%s\"" + strings.Join(archs, " ")), "VERSION=" + version}); err != nil {
		return err
	}
	return nil
}

func InitImage(version string) error {
	if _, err := command.Make([]string{"image-init"}, []string{"VERSION=" + version}); err != nil {
		return err
	}
	return nil
}
