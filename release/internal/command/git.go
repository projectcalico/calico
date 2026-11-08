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

import "strings"

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

// Resolve returns the commit a ref names. A missing ref fails like any other
// error, so both report false.
func (g GitRunner) Resolve(ref string) (string, bool) {
	out, err := g.Run("rev-parse", "--verify", "--quiet", ref)
	return out, err == nil && out != ""
}

// IsAncestor reports whether a is an ancestor of b. A missing ref reports false.
func (g GitRunner) IsAncestor(a, b string) bool {
	_, err := g.Run("merge-base", "--is-ancestor", a, b)
	return err == nil
}

func (g GitRunner) Run(args ...string) (string, error) {
	return g.r.Run("git", args, WithDir(g.dir))
}

// GitInDir runs a git command in a specific directory.
func GitInDir(dir string, args ...string) (string, error) {
	return Git(&RealCommandRunner{}).In(dir).Run(args...)
}

func GitVersion(includeDirty bool, opts ...Option) (string, error) {
	return Git(&RealCommandRunner{}).In(newSettings(opts).dir).Version(includeDirty)
}

// GitDir returns the root directory of the git repository.
func GitDir() (string, error) {
	return Git(&RealCommandRunner{}).RepoRoot()
}

func GitDirty(dir string) (bool, error) {
	return Git(&RealCommandRunner{}).In(dir).Dirty()
}

func GitBranch(dir string) (string, error) {
	return Git(&RealCommandRunner{}).In(dir).Branch()
}
