package builder

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// CommandRunner runs the given command. Useful for mocking commands in unit tests.
type CommandRunner interface {
	// Run takes the command to run, a list of args, and list of environment variables
	// in the form A=B, and returns stdout / error.
	Run(string, []string, []string) (string, error)
	RunNoCapture(string, []string, []string) error

	RunInDir(string, string, []string, []string) (string, error)
	RunInDirNoCapture(string, string, []string, []string) error
}

// RealCommandRunner runs a command for real on the host.
type RealCommandRunner struct{}

func (r *RealCommandRunner) RunInDir(dir, name string, args []string, env []string) (string, error) {
	cmd := exec.Command(name, args...)
	if len(env) != 0 {
		cmd.Env = env
	}
	cmd.Dir = dir
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	logrus.WithField("cmd", cmd.String()).Infof("Running %s command", name)
	err := cmd.Run()
	logrus.Debug(outb.String())
	if err != nil {
		err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(outb.String()), err
}

func (r *RealCommandRunner) RunInDirNoCapture(dir, name string, args []string, env []string) error {
	cmd := exec.Command(name, args...)
	if len(env) != 0 {
		cmd.Env = env
	}
	cmd.Stdout = io.Writer(os.Stdout)
	cmd.Stderr = io.Writer(os.Stderr)
	cmd.Dir = dir
	logrus.WithField("cmd", cmd.String()).Infof("Running %s command", name)
	err := cmd.Run()
	return err
}

func (r *RealCommandRunner) Run(name string, args []string, env []string) (string, error) {
	return r.RunInDir("", name, args, env)
}

func (r *RealCommandRunner) RunNoCapture(name string, args []string, env []string) error {
	return r.RunInDirNoCapture("", name, args, env)
}
