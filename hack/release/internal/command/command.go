// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Run executes a command and returns its trimmed stdout.
func Run(name string, args, env []string) (string, error) {
	return RunInDir("", name, args, env)
}

// RunInDir executes a command in the given directory and returns its trimmed stdout.
func RunInDir(dir, name string, args, env []string) (string, error) {
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
	}).Debugf("Running %s command", name)
	err := cmd.Run()
	if err != nil {
		errDesc := fmt.Sprintf(`running command "%s %s"`, name, strings.Join(args, " "))
		if dir != "" {
			errDesc += fmt.Sprintf(" in directory %s", dir)
		}
		err = fmt.Errorf("%s: %w \n%s", errDesc, err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(outb.String()), err
}

// MakeInDir runs make with the provided targets and environment variables in the specified directory.
func MakeInDir(dir string, targets string, env ...string) (string, error) {
	logrus.WithFields(logrus.Fields{
		"targets": targets,
		"dir":     dir,
	}).Info("Running make")
	return RunInDir(dir, "make", strings.Fields(targets), env)
}
