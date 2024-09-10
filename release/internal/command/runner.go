package command

func runner() CommandRunner {
	return &RealCommandRunner{}
}

// Run runs a command with arguments.
func Run(command string, args []string) (string, error) {
	return runner().Run(command, args, nil)
}
