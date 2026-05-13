// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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
	"path/filepath"
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

	// RunInDirToFile behaves like RunInDir, but additionally writes a copy of stdout
	// and stderr to logPath. Use this for long-running commands whose output is
	// worth retaining as a standalone artifact (e.g., per-component build/publish
	// logs from a release run).
	RunInDirToFile(string, string, []string, []string, string) (string, error)
}

// RealCommandRunner runs a command for real on the host.
type RealCommandRunner struct{}

func (r *RealCommandRunner) RunInDir(dir, name string, args []string, env []string) (string, error) {
	return r.runInDir(dir, name, args, env, nil, nil)
}

func (r *RealCommandRunner) RunInDirToFile(dir, name string, args []string, env []string, logPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return "", fmt.Errorf("create log dir %s: %w", filepath.Dir(logPath), err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		return "", fmt.Errorf("create log file %s: %w", logPath, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			logrus.WithError(cerr).Warnf("Failed to close log file %s", logPath)
		}
	}()
	return r.runInDir(dir, name, args, env, f, f)
}

// runInDir is the shared implementation. extraOut and extraErr (if non-nil) receive
// a copy of the child's stdout / stderr in addition to the captured buffer and the
// live os.Stdout / os.Stderr stream.
func (r *RealCommandRunner) runInDir(dir, name string, args, env []string, extraOut, extraErr io.Writer) (string, error) {
	cmd := exec.Command(name, args...)
	if len(env) != 0 {
		cmd.Env = env
	}
	cmd.Dir = dir

	// Capture into a buffer for the return value, and (when given) tee to a
	// log file so callers always have a persistent copy. Streaming to the
	// parent's stdout/stderr is gated on debug to preserve the previous
	// quiet default for non-debug runs.
	//
	// We deliberately don't pipe through logrus.WriterLevel: it sits on a
	// synchronous io.Pipe whose scanner goroutine bails out on any line longer
	// than bufio.MaxScanTokenSize, and after that the pipe has no reader and
	// the next write from the child deadlocks. docker buildx progress output
	// is exactly the kind of input that trips this.
	var outb, errb bytes.Buffer
	stdoutWriters := []io.Writer{&outb}
	stderrWriters := []io.Writer{&errb}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}
	if extraOut != nil {
		stdoutWriters = append(stdoutWriters, extraOut)
	}
	if extraErr != nil {
		stderrWriters = append(stderrWriters, extraErr)
	}
	cmd.Stdout = io.MultiWriter(stdoutWriters...)
	cmd.Stderr = io.MultiWriter(stderrWriters...)

	logrus.WithFields(logrus.Fields{
		"cmd": cmd.String(),
		"dir": dir,
	}).Debugf("Running %s command", name)
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
	}).Debugf("Running %s command", name)
	err := cmd.Run()
	return err
}

func (r *RealCommandRunner) Run(name string, args []string, env []string) (string, error) {
	return r.RunInDir("", name, args, env)
}

func (r *RealCommandRunner) RunNoCapture(name string, args []string, env []string) error {
	return r.RunInDirNoCapture("", name, args, env)
}
