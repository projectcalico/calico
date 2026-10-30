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

// GitInDir runs a git command in a specific directory.
func GitInDir(dir string, args ...string) (string, error) {
	return git(args, WithDir(dir))
}

func git(args []string, opts ...Option) (string, error) {
	s := &settings{
		name:   "git",
		args:   args,
		runner: runner(),
	}
	for _, o := range opts {
		o.apply(s)
	}
	return run(s)
}

func GitVersion(dir string, includeDirty bool, opts ...Option) (string, error) {
	args := []string{"describe", "--tags", "--always", "--long", "--abbrev=12"}
	if includeDirty {
		args = append(args, "--dirty")
	}
	return git(args, append(opts, WithDir(dir))...)
}

// GitDir returns the root directory of the git repository.
func GitDir() (string, error) {
	args := []string{"rev-parse", "--show-toplevel"}
	return git(args)
}
