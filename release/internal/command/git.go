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
	"errors"
	"fmt"
	"strings"
)

// ErrGitRefNotFound is what Resolve returns for a ref that names no commit.
var ErrGitRefNotFound = errors.New("ref not found")

// GitRunner runs git in the cwd, or in the dir In binds.
type GitRunner struct {
	r   CommandRunner
	dir string
}

func Git(r CommandRunner) GitRunner {
	return GitRunner{r: r}
}

func (g GitRunner) In(dir string) GitRunner {
	g.dir = dir
	return g
}

func (g GitRunner) RepoRoot() (string, error) {
	return g.Run("rev-parse", "--show-toplevel")
}

func (g GitRunner) Branch() (string, error) {
	return g.Run("rev-parse", "--abbrev-ref", "HEAD")
}

func (g GitRunner) Version(includeDirty bool) (string, error) {
	args := []string{"describe", "--tags", "--always", "--long", "--abbrev=12"}
	if includeDirty {
		args = append(args, "--dirty")
	}
	return g.Run(args...)
}

// Dirty reports tracked files with uncommitted changes. Porcelain also counts
// untracked files.
func (g GitRunner) Dirty() (bool, error) {
	v, err := g.Version(true)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(v, "-dirty"), nil
}

func (g GitRunner) Porcelain() (bool, error) {
	out, err := g.Run("status", "--porcelain")
	if err != nil {
		return false, err
	}
	return out != "", nil
}

// Resolve returns the commit a ref names.
func (g GitRunner) Resolve(ref string) (string, error) {
	out, err := g.Run("rev-parse", "--verify", "--quiet", ref)
	if exitCode(err) == 1 {
		return "", fmt.Errorf("resolve %s: %w", ref, ErrGitRefNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	return out, nil
}

// IsAncestor reports whether a is an ancestor of b. A missing ref is an error.
func (g GitRunner) IsAncestor(a, b string) (bool, error) {
	_, err := g.Run("merge-base", "--is-ancestor", a, b)
	switch {
	case err == nil:
		return true, nil
	case exitCode(err) == 1:
		return false, nil
	}
	return false, fmt.Errorf("check %s is an ancestor of %s: %w", a, b, err)
}

func exitCode(err error) int {
	if cerr, ok := errors.AsType[*Error](err); ok {
		return cerr.ExitCode
	}
	return 0
}

func (g GitRunner) Run(args ...string) (string, error) {
	return g.r.Run("git", args, WithDir(g.dir))
}
