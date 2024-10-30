// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

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
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		// If debug level is enabled, also write to stdout.
		cmd.Stdout = io.MultiWriter(os.Stdout, &outb)
		cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
	} else {
		// Otherwise, just capture the output to return.
		cmd.Stdout = io.MultiWriter(&outb)
		cmd.Stderr = io.MultiWriter(&errb)
	}
	logrus.WithFields(logrus.Fields{
		"cmd": cmd.String(),
		"dir": dir,
	}).Infof("Running %s command", name)
	err := cmd.Run()
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
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logrus.WithFields(logrus.Fields{
		"cmd": cmd.String(),
		"dir": dir,
	}).Infof("Running %s command", name)
	err := cmd.Run()
	return err
}

func (r *RealCommandRunner) Run(name string, args []string, env []string) (string, error) {
	return r.RunInDir("", name, args, env)
}

func (r *RealCommandRunner) RunNoCapture(name string, args []string, env []string) error {
	return r.RunInDirNoCapture("", name, args, env)
}
