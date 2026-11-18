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

package branch

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

func localBranchExists(g command.GitRunner, name string) (bool, error) {
	_, err := g.Resolve("refs/heads/" + name)
	if err != nil {
		return false, ignoreMissingRef(err)
	}
	return true, nil
}

// createBranch creates a local branch at base without switching HEAD.
func createBranch(g command.GitRunner, name, base string) error {
	if _, err := g.Run("branch", name, base); err != nil {
		return fmt.Errorf("create branch %s at %s: %w", name, base, err)
	}
	return nil
}

// createAndCheckoutBranch creates a branch at base and checks it out so later
// steps act on it.
func createAndCheckoutBranch(g command.GitRunner, name, base string) error {
	if err := createBranch(g, name, base); err != nil {
		return err
	}
	return checkoutBranch(g, name)
}

// resetBranchToBase points name at base's head and checks it out, creating it if
// absent, so a re-cut picks up source changes.
func resetBranchToBase(g command.GitRunner, name, base string) error {
	if _, err := g.Run("checkout", "-B", name, base); err != nil {
		return fmt.Errorf("reset branch %s to %s: %w", name, base, err)
	}
	return nil
}

// sourceAheadOf reports whether source has commits the branch lacks (source is
// not an ancestor of branch).
func sourceAheadOf(g command.GitRunner, source, branch string) (bool, error) {
	isAncestor, err := g.IsAncestor(source, branch)
	return !isAncestor, err
}

// checkoutBranch switches HEAD to name. It is idempotent: checking out the
// branch already at HEAD is a no-op.
func checkoutBranch(g command.GitRunner, name string) error {
	if _, err := g.Run("checkout", name); err != nil {
		return fmt.Errorf("checkout %s: %w", name, err)
	}
	return nil
}

// stageAndCommit commits paths with msg, returning whether it committed.
// Scoped to paths so a dirty-tree resume cannot sweep in unrelated staged changes.
func stageAndCommit(g command.GitRunner, msg string, paths []string) (bool, error) {
	if len(paths) == 0 {
		return false, nil
	}
	if _, err := g.Run(append([]string{"add"}, paths...)...); err != nil {
		return false, fmt.Errorf("git add: %w", err)
	}
	diff := append([]string{"diff", "--cached", "--quiet", "--"}, paths...)
	_, err := g.Run(diff...)
	if err == nil {
		// exit 0 = our paths are unchanged; skip the commit so re-runs don't fail.
		return false, nil
	}
	if cerr, ok := errors.AsType[*command.Error](err); !ok || cerr.ExitCode != 1 {
		return false, fmt.Errorf("git diff: %w", err)
	}
	commit := append([]string{"commit", "-m", msg, "--"}, paths...)
	if _, err := g.Run(commit...); err != nil {
		return false, fmt.Errorf("git commit: %w", err)
	}
	return true, nil
}

// localTagPointsAt reports whether the local tag is on branch's head. A missing
// tag or branch reports false, so a resume knows to create it.
func localTagPointsAt(g command.GitRunner, tagName, branch string) (bool, error) {
	tagSha, err := g.Resolve("refs/tags/" + tagName)
	if err != nil {
		return false, ignoreMissingRef(err)
	}
	branchSha, err := g.Resolve("refs/heads/" + branch)
	if err != nil {
		return false, ignoreMissingRef(err)
	}
	return tagSha == branchSha, nil
}

func ignoreMissingRef(err error) error {
	if errors.Is(err, command.ErrGitRefNotFound) {
		return nil
	}
	return err
}

// tag force-creates tagName. -f is safe: a remote collision is advanced past
// earlier, so any tag met here is local-only and safe to move.
func tag(g command.GitRunner, tagName string) error {
	if _, err := g.Run("tag", "-f", "--no-sign", tagName); err != nil {
		return fmt.Errorf("tag %s: %w", tagName, err)
	}
	return nil
}

// tagWithEmptyCommit adds an empty "Begin development" commit on branch and tags
// it, for a target whose dev tag must sit on a fresh commit. Leaves HEAD there.
func tagWithEmptyCommit(g command.GitRunner, branch, tagName string) error {
	if err := checkoutBranch(g, branch); err != nil {
		return err
	}
	if _, err := g.Run("commit", "--allow-empty", "-m", "Begin development for "+tagName); err != nil {
		return fmt.Errorf("create commit on %s: %w", branch, err)
	}
	return tag(g, tagName)
}

// tagHead tags branch's head with no new commit, for the derived branch whose
// head already carries the edits commit. Leaves HEAD there.
func tagHead(g command.GitRunner, branch, tagName string) error {
	if err := checkoutBranch(g, branch); err != nil {
		return err
	}
	return tag(g, tagName)
}

// remoteRefMatches reports whether ref exists on remote and whether it points at
// localSha. ls-remote may return several lines (a name that is both a branch and
// a tag); a match on any line counts, so callers pass names unique to one ref.
func remoteRefMatches(g command.GitRunner, remote, ref, localSha string) (present, matches bool, err error) {
	out, err := g.Run("ls-remote", remote, ref)
	if err != nil {
		return false, false, err
	}
	present = false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line) // "<sha>\t<ref>"
		if len(fields) == 0 {
			continue
		}
		present = true
		if fields[0] == localSha {
			return true, true, nil
		}
	}
	return present, false, nil
}

// pushRefs pushes the given refs to remote.
func pushRefs(g command.GitRunner, remote string, dryRun bool, refs ...string) error {
	args := []string{"push", remote}
	if dryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, refs...)
	_, err := g.Run(args...)
	return err
}

// checkBranchCurrent verifies branch's local tip equals its remote counterpart,
// never moving it. recovery is the fix hint shown when it is not current.
func checkBranchCurrent(g command.GitRunner, branch, remote string, requireCurrent, report bool, recovery string) error {
	// An empty remote reads the branch's upstream from .git/config. A missing or
	// broken upstream is an error: without it the cut cannot verify the branch is
	// current, so the operator must set a valid tracking branch first.
	upstream := remote + "/" + branch
	if remote == "" {
		out, err := g.Run("rev-parse", "--abbrev-ref", "--symbolic-full-name", branch+"@{upstream}")
		if err != nil {
			return fmt.Errorf("%s has no valid upstream; set one with `git branch --set-upstream-to=<remote>/%s %s`", branch, branch, branch)
		}
		upstream = strings.TrimSpace(out)
		remote, _, _ = strings.Cut(upstream, "/")
	}

	if _, err := g.Run("fetch", remote); err != nil {
		return fmt.Errorf("fetching %s to check %s is current: %w", remote, branch, err)
	}
	local, err := g.Resolve(branch)
	if err := ignoreMissingRef(err); err != nil {
		return err
	}
	up, err := g.Resolve(upstream)
	if err := ignoreMissingRef(err); err != nil {
		return err
	}
	if up != "" && local == up {
		return nil // current
	}

	// Not current: any difference, or no counterpart on the remote. recovery is
	// the caller's fix hint.
	reason := fmt.Sprintf("%s is not in sync with %s", branch, upstream)
	switch {
	case report:
		logrus.Warnf("%s; a cut will error unless resolved: %s", reason, recovery)
	case requireCurrent:
		return fmt.Errorf("%s; %s", reason, recovery)
	default:
		logrus.Warnf("%s; cutting from the local branch as is", reason)
	}
	return nil
}
