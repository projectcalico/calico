package command

// Make runs a make command.
func Make(args []string, envs []string) (string, error) {
	return runner().Run("make", args, envs)
}

// MakeInDir runs a make command in a specific directory.
func MakeInDir(dir string, args []string, envs []string) (string, error) {
	args = append([]string{"-C", dir}, args...)
	return Make(args, envs)
}
