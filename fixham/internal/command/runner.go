package command

import (
	"github.com/projectcalico/calico/hack/release/pkg/builder"
)

func runner() builder.CommandRunner {
	return &builder.RealCommandRunner{}
}

func Run(command string, args []string) (string, error) {
	return runner().Run(command, args, nil)
}

func Metadata(dir, calicoVersion, operatorVersion string) error {
	r := builder.NewReleaseBuilder(runner())
	return r.BuildMetadataWithVersions(dir, calicoVersion, operatorVersion)
}
