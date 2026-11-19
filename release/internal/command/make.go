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
	"fmt"
	"slices"
	"strings"
)

// MakeRunner runs make in one directory.
type MakeRunner struct {
	r   CommandRunner
	dir string
}

// Make takes a dir because a make run from the wrong directory reads the
// wrong Makefile, or none.
func Make(r CommandRunner, dir string) MakeRunner {
	return MakeRunner{r: r, dir: dir}
}

// Run runs make with args.
func (m MakeRunner) Run(args []string, opts ...Option) (string, error) {
	return m.run(args, opts)
}

// Print runs a target only for what it prints: make adds no output of its own.
func (m MakeRunner) Print(target string, opts ...Option) (string, error) {
	if len(strings.Fields(target)) > 1 {
		return "", &Error{Err: fmt.Errorf("expected a single target, got %q", target)}
	}
	return m.run([]string{"-s", "--no-print-directory", target}, opts)
}

func (m MakeRunner) run(args []string, opts []Option) (string, error) {
	return m.r.Run("make", args, append(slices.Clip(opts), WithDir(m.dir))...)
}
