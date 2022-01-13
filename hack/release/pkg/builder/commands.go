package builder

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// CommandRunner runs the given command. Useful for mocking commands in unit tests.
type CommandRunner interface {
	// Run takes the command to run, a list of args, and list of environment variables
	// in the form A=B, and returns stdout / error.
	Run(string, []string, []string) (string, error)
}

// RealCommandRunner runs a command for real on the host.
type RealCommandRunner struct {
}

func (r *RealCommandRunner) Run(name string, args []string, env []string) (string, error) {
	cmd := exec.Command(name, args...)
	if len(env) != 0 {
		cmd.Env = env
	}
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

// EchoRunner simply echos back the command that is given, and returns a pre-canned
// response / error if specified.
type EchoRunner struct {
	responses map[string]string
	errors    map[string]error
	history   []string
}

func (r *EchoRunner) Run(name string, args []string, env []string) (string, error) {
	if r.history == nil {
		r.history = []string{}
	}
	command := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	logrus.WithField("env", env).Infof("ECHO: %s", command)
	r.history = append(r.history, command)
	return r.responses[command], r.errors[command]
}
