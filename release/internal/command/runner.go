package command

import "github.com/projectcalico/calico/release/pkg/builder"

func runner() builder.CommandRunner {
	return &builder.RealCommandRunner{}
}

// Run runs a command with arguments.
func Run(command string, args []string) (string, error) {
	return runner().Run(command, args, nil)
}
