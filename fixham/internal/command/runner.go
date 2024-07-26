package command

import (
	"github.com/projectcalico/calico/hack/release/pkg/builder"
)

func runner() builder.CommandRunner {
	return &builder.RealCommandRunner{}
}

// Builder returns a new release builder.
func Builder() *builder.ReleaseBuilder {
	return builder.NewReleaseBuilder(runner())
}

// Run runs a command with arguments.
func Run(command string, args []string) (string, error) {
	return runner().Run(command, args, nil)
}
