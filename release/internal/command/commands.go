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
	"errors"
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
	// Run returns the command's trimmed stdout. A command that fails returns an *Error.
	// For git and make, call Git(r) or Make(r, dir) instead.
	Run(name string, args []string, opts ...Option) (string, error)
}

// realCommandRunner runs a command for real on the host.
type realCommandRunner struct{}

// RealRunner is the runner for commands that must run on the host.
var RealRunner CommandRunner = &realCommandRunner{}

// Runner returns r, or RealRunner when r is nil, so a zero-value
// config runs real commands.
func Runner(r CommandRunner) CommandRunner {
	if r == nil {
		return RealRunner
	}
	return r
}

func (r *realCommandRunner) Run(name string, args []string, opts ...Option) (string, error) {
	s := newSettings(opts)
	cmd := exec.Command(name, args...)
	if len(s.env) != 0 {
		cmd.Env = append(os.Environ(), s.env...)
	}
	cmd.Dir = s.dir
	if s.stdin != "" {
		cmd.Stdin = strings.NewReader(s.stdin)
	}

	// We deliberately don't pipe through logrus.WriterLevel: it sits on a
	// synchronous io.Pipe whose scanner goroutine bails out on any line longer
	// than bufio.MaxScanTokenSize, and after that the pipe has no reader and
	// the next write from the child deadlocks. docker buildx progress output
	// is exactly the kind of input that trips this.
	var outb, errb bytes.Buffer
	stdoutWriters := []io.Writer{&outb}
	stderrWriters := []io.Writer{&errb}
	streamed := s.stream || logrus.IsLevelEnabled(logrus.DebugLevel)
	if streamed {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}
	if s.logFile != "" {
		f, err := createLogFile(s.logFile)
		if err != nil {
			return "", err
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				logrus.WithError(cerr).Warnf("Failed to close log file %s", s.logFile)
			}
		}()
		stdoutWriters = append(stdoutWriters, f)
		stderrWriters = append(stderrWriters, f)
	}
	cmd.Stdout = io.MultiWriter(stdoutWriters...)
	cmd.Stderr = io.MultiWriter(stderrWriters...)

	logrus.WithFields(logrus.Fields{
		"cmd": cmd.String(),
		"dir": s.dir,
	}).Debugf("Running %s command", name)
	err := cmd.Run()
	out := strings.TrimSpace(outb.String())
	if err != nil {
		code := -1
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exit.ExitCode()
		}
		return out, &Error{Stdout: out, Stderr: strings.TrimSpace(errb.String()), Err: err, ExitCode: code, streamed: streamed}
	}
	return out, nil
}

func createLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create log file %s: %w", path, err)
	}
	return f, nil
}

// Error is a command that ran and failed. Many tools (make in particular)
// report the actual failure on stdout, so it is kept alongside stderr.
type Error struct {
	Stdout string
	Stderr string
	Err    error
	// ExitCode is -1 when the command did not exit normally.
	ExitCode int

	// streamed means stdout already reached the terminal, so Error leaves it out.
	streamed bool
}

const errorStdoutLines = 50

func (e *Error) Error() string {
	msg := fmt.Sprintf("%s: %s", e.Err, e.Stderr)
	if !e.streamed {
		if tail := lastLines(e.Stdout, errorStdoutLines); tail != "" {
			msg = fmt.Sprintf("%s\nlast %d lines of stdout:\n%s", msg, errorStdoutLines, tail)
		}
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
