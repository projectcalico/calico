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

//go:build fv

package branch

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// tagReleased tags HEAD as a release, then commits past it so the tag is not main's head.
func tagReleased(t *testing.T, root, tagName string, push bool) string {
	t.Helper()
	run := func(args ...string) string {
		out, err := realGit(root).Run(args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(out)
	}
	run("config", "tag.gpgsign", "false")
	run("tag", "-a", tagName, "-m", "Release "+tagName)
	if push {
		run("push", "-q", "origin", tagName)
	}
	sha := run("rev-parse", tagName+"^{commit}")
	run("commit", "-q", "--allow-empty", "-m", "after the release")
	return sha
}

func TestCutFromTag(t *testing.T) {
	// A cut from a released tag branches at the tag, never touches main, and pushes
	// only the derived branch.
	t.Run("cuts from a released tag", func(t *testing.T) {
		root := initGitRepo(t)
		remote := initGitRemote(t, root)
		released := tagReleased(t, root, "v3.23.1", true)
		mainBefore, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}

		derived := "release-v3.23.1-hotfix"
		d := newTestDriver(t, Driver{
			RepoRoot: root,
			Validate: true,
			Publish:  true,
			PrepareDerived: func(string) ([]string, error) {
				writeFile(t, root, "metadata.mk", "MANAGER_BRANCH ?= "+derived+"\n")
				return []string{"metadata.mk"}, nil
			},
		})
		if err := d.CutReleaseBranch(&CutPlan{Derived: derived, Source: TagSource("v3.23.1"), Remote: "origin"}); err != nil {
			t.Fatal(err)
		}

		// The derived branch is the tag plus the edits commit.
		parent, err := realGit(root).Run("rev-parse", derived+"^")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(released, strings.TrimSpace(parent)); diff != "" {
			t.Fatalf("strings.TrimSpace(parent) mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff("Updates for "+derived+" release branch", gitHeadSubject(t, root, derived)); diff != "" {
			t.Fatalf("gitHeadSubject(t, root, derived) mismatch (-want +got):\n%s", diff)
		}

		// It is on the remote; main is untouched and no dev tag was made.
		onRemote, err := realGit(remote).Run("rev-parse", derived)
		if err != nil {
			t.Fatal(err)
		}
		local, err := realGit(root).Run("rev-parse", derived)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(strings.TrimSpace(local), strings.TrimSpace(onRemote)); diff != "" {
			t.Fatalf("strings.TrimSpace(onRemote) mismatch (-want +got):\n%s", diff)
		}
		mainAfter, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(mainBefore, mainAfter); diff != "" {
			t.Fatalf("mainAfter mismatch (-want +got):\n%s", diff)
		}
		tags, err := realGit(remote).Run("tag", "--list")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff("v3.23.1", strings.TrimSpace(tags)); diff != "" {
			t.Fatalf("strings.TrimSpace(tags) mismatch (-want +got):\n%s", diff)
		}
	})

	// A cut from a tag never advances main, so a plan that would is rejected.
	t.Run("rejects a main target", func(t *testing.T) {
		root := initGitRepo(t)
		initGitRemote(t, root)
		tagReleased(t, root, "v3.23.1", true)
		mainBefore, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}

		d := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Publish: true})
		err = d.CutReleaseBranch(&CutPlan{
			Derived:    "release-v3.23.1-hotfix",
			Source:     TagSource("v3.23.1"),
			Remote:     "origin",
			TagTargets: []TagTarget{{Branch: "master", DevTag: "v3.24.0-0.dev"}},
		})
		if err == nil || !strings.Contains(err.Error(), "a cut from v3.23.1 cannot advance master") {
			t.Fatalf("error = %v, want one containing %q", err, "a cut from v3.23.1 cannot advance master")
		}

		if branchExists(t, realGit(root), "release-v3.23.1-hotfix") {
			t.Fatal("localBranchExists(realGit(root), \"release-v3.23.1-hotfix\") = true")
		}
		mainAfter, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(mainBefore, mainAfter); diff != "" {
			t.Fatalf("mainAfter mismatch (-want +got):\n%s", diff)
		}
	})

	// A plan-mode preview of a cut from an unreleased tag warns and makes no branch.
	t.Run("plan mode previews an unreleased tag", func(t *testing.T) {
		root := initGitRepo(t)
		initGitRemote(t, root)
		tagReleased(t, root, "v3.23.2", false)

		d := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Plan: true})
		if err := d.CutReleaseBranch(&CutPlan{Derived: "release-v3.23.2-hotfix", Source: TagSource("v3.23.2"), Remote: "origin"}); err != nil {
			t.Fatal(err)
		}
		if branchExists(t, realGit(root), "release-v3.23.2-hotfix") {
			t.Fatal("localBranchExists(realGit(root), \"release-v3.23.2-hotfix\") = true")
		}
	})

	// Only a tag the remote released can be cut from.
	t.Run("only a tag the remote released can be cut", func(t *testing.T) {
		root := initGitRepo(t)
		initGitRemote(t, root)
		g := realGit(root)

		tagReleased(t, root, "v3.23.1", true)
		if err := checkTagOnRemote(g, "v3.23.1", "origin", false); err != nil {
			t.Fatal(err)
		}

		if err := checkTagOnRemote(g, "v3.23.9", "origin", false); err == nil || !strings.Contains(err.Error(), "does not exist locally") {
			t.Fatalf("error = %v, want one containing %q", err, "does not exist locally")
		}

		tagReleased(t, root, "v3.23.2", false)
		if err := checkTagOnRemote(g, "v3.23.2", "origin", false); err == nil || !strings.Contains(err.Error(), "is not on origin") {
			t.Fatalf("error = %v, want one containing %q", err, "is not on origin")
		}
		// Plan mode previews the cut with a warning instead.
		if err := checkTagOnRemote(g, "v3.23.2", "origin", true); err != nil {
			t.Fatal(err)
		}

		// A local tag that moved from what was released is rejected.
		_, err := realGit(root).Run("tag", "-f", "-a", "v3.23.1", "-m", "moved")
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTagOnRemote(g, "v3.23.1", "origin", false); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error = %v, want one containing %q", err, "does not match")
		}
		if err := checkTagOnRemote(g, "v3.23.1", "origin", true); err != nil {
			t.Fatal(err)
		}

		// A remote that cannot be queried fails even in plan mode.
		if err := checkTagOnRemote(g, "v3.23.1", "no-such-remote", true); err == nil || !strings.Contains(err.Error(), "checking refs/tags/v3.23.1 on no-such-remote") {
			t.Fatalf("error = %v, want one containing %q", err, "checking refs/tags/v3.23.1 on no-such-remote")
		}
	})
}
