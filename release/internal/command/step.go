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
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// One retry: pushes fail on network flakes often enough to save a run.
const MaxRetries = 1

// Step holds what every release step needs: a runner, where to run, and the
// step's own name. Embedding keeps them unexported, so a zero-value config
// still runs real commands.
type Step struct {
	runner CommandRunner

	// dir is where commands run. Empty runs them in the current directory.
	dir string

	// name identifies the step in logs, errors and log paths.
	name string

	// logsDir is where per-invocation logs are written. Empty captures the
	// output in memory instead.
	logsDir string
}

// Option overrides a default on a step.
type Option func(*Step)

// WithRunner substitutes the runner commands are driven through.
func WithRunner(r CommandRunner) Option {
	return func(s *Step) { s.runner = r }
}

// WithName identifies the step in its logs, errors and log paths.
func WithName(name string) Option {
	return func(s *Step) { s.name = name }
}

// WithLogsDir writes each invocation's output to a file under dir.
func WithLogsDir(dir string) Option {
	return func(s *Step) { s.logsDir = dir }
}

// WithDir sets the directory commands run in.
func WithDir(dir string) Option {
	return func(s *Step) { s.dir = dir }
}

// Apply layers the options over the step.
func (s *Step) Apply(opts []Option) {
	for _, opt := range opts {
		opt(s)
	}
}

// Runner returns the runner to drive commands through, defaulting to real ones.
func (s Step) Runner() CommandRunner {
	if s.runner == nil {
		return &RealCommandRunner{}
	}
	return s.runner
}

// Run sends output to logPath when there is one, else captures it in memory.
func (s Step) Run(name string, args, env []string, logPath string) (string, error) {
	if logPath == "" {
		return s.Runner().RunInDir(s.dir, name, args, env)
	}
	return s.Runner().RunInDirToFile(s.dir, name, args, env, logPath)
}

// Name is the step's own name, as it appears in logs and errors.
func (s Step) Name() string {
	return s.name
}

// Logger tags every line with the step, so a release running several steps
// produces output a reader can tell apart.
func (s Step) Logger() *logrus.Entry {
	return logrus.WithField("step", s.name)
}

// Errorf prefixes an error with the step that produced it.
func (s Step) Errorf(format string, args ...any) error {
	return fmt.Errorf("%s: %w", s.name, fmt.Errorf(format, args...))
}

// LogPath is where one invocation's output goes, named by slug. Steps sharing
// a name write to the same directory, so the slug is what keeps them apart.
// An empty logs dir captures the output in memory instead.
func (s Step) LogPath(slug string) string {
	if s.logsDir == "" {
		return ""
	}
	return filepath.Join(s.logsDir, s.name, slug+".log")
}
