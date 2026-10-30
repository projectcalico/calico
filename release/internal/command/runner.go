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

func runner() CommandRunner {
	return &RealCommandRunner{}
}

type Option interface {
	apply(*settings)
}

type setting func(*settings)

func (f setting) apply(s *settings) { f(s) }

type settings struct {
	name   string
	dir    string
	args   []string
	runner CommandRunner
}

func WithDir(dir string) Option {
	return setting(func(s *settings) {
		s.dir = dir
	})
}

func WithRunner(runner CommandRunner) Option {
	return setting(func(s *settings) {
		s.runner = runner
	})
}

func run(s *settings) (string, error) {
	return s.runner.RunInDir(s.dir, s.name, s.args, nil)
}

// Run runs a command with arguments.
func Run(command string, args []string) (string, error) {
	return runner().Run(command, args, nil)
}

// RunInDir runs a command with arguments in a specific directory.
func RunInDir(dir, command string, args []string) (string, error) {
	return runner().RunInDir(dir, command, args, nil)
}
