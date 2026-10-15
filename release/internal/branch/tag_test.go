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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/command"
)

// tagReleased tags HEAD as a release, then commits past it so the tag is not main's head.
func tagReleased(t *testing.T, root, tagName string, push bool) string {
	t.Helper()
	run := func(args ...string) string {
		out, err := command.GitInDir(root, args...)
		require.NoError(t, err, "git %v", args)
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

// A cut from a released tag branches at the tag, never touches main, and pushes
// only the derived branch.
func TestCutFromTag(t *testing.T) {
	root := initGitRepo(t)
	remote := initGitRemote(t, root)
	released := tagReleased(t, root, "v3.23.1", true)
	mainBefore, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)

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
	require.NoError(t, d.CutReleaseBranch(&CutPlan{Derived: derived, Source: TagSource("v3.23.1"), Remote: "origin"}))

	// The derived branch is the tag plus the edits commit.
	parent, err := command.GitInDir(root, "rev-parse", derived+"^")
	require.NoError(t, err)
	require.Equal(t, released, strings.TrimSpace(parent))
	require.Equal(t, "Updates for "+derived+" release branch", gitHeadSubject(t, root, derived))

	// It is on the remote; main is untouched and no dev tag was made.
	onRemote, err := command.GitInDir(remote, "rev-parse", derived)
	require.NoError(t, err)
	local, err := command.GitInDir(root, "rev-parse", derived)
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(local), strings.TrimSpace(onRemote))
	mainAfter, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)
	require.Equal(t, mainBefore, mainAfter)
	tags, err := command.GitInDir(remote, "tag", "--list")
	require.NoError(t, err)
	require.Equal(t, "v3.23.1", strings.TrimSpace(tags))
}

// Only a tag the remote released can be cut from.
func TestCheckTagOnRemote(t *testing.T) {
	root := initGitRepo(t)
	initGitRemote(t, root)
	g := gitIn(root)

	tagReleased(t, root, "v3.23.1", true)
	require.NoError(t, checkTagOnRemote(g, "v3.23.1", "origin", false))

	require.ErrorContains(t, checkTagOnRemote(g, "v3.23.9", "origin", false), "does not exist locally")

	tagReleased(t, root, "v3.23.2", false)
	require.ErrorContains(t, checkTagOnRemote(g, "v3.23.2", "origin", false), "is not on origin")
	// Plan mode previews the cut with a warning instead.
	require.NoError(t, checkTagOnRemote(g, "v3.23.2", "origin", true))

	// A local tag that moved from what was released is rejected.
	_, err := command.GitInDir(root, "tag", "-f", "-a", "v3.23.1", "-m", "moved")
	require.NoError(t, err)
	require.ErrorContains(t, checkTagOnRemote(g, "v3.23.1", "origin", false), "does not match")
	require.NoError(t, checkTagOnRemote(g, "v3.23.1", "origin", true))

	// A remote that cannot be queried fails even in plan mode.
	require.ErrorContains(t, checkTagOnRemote(g, "v3.23.1", "no-such-remote", true), "checking refs/tags/v3.23.1 on no-such-remote")
}

// A cut from a tag never advances main, so a plan that would is rejected.
func TestCutFromTagRejectsMainTarget(t *testing.T) {
	root := initGitRepo(t)
	initGitRemote(t, root)
	tagReleased(t, root, "v3.23.1", true)
	mainBefore, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)

	d := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Publish: true})
	err = d.CutReleaseBranch(&CutPlan{
		Derived:    "release-v3.23.1-hotfix",
		Source:     TagSource("v3.23.1"),
		Remote:     "origin",
		TagTargets: []TagTarget{{Branch: "master", DevTag: "v3.24.0-0.dev"}},
	})
	require.ErrorContains(t, err, "a cut from v3.23.1 cannot advance master")

	require.False(t, localBranchExists(gitIn(root), "release-v3.23.1-hotfix"))
	mainAfter, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)
	require.Equal(t, mainBefore, mainAfter)
}

// A plan-mode preview of a cut from an unreleased tag warns and makes no branch.
func TestCutFromTagPlan(t *testing.T) {
	root := initGitRepo(t)
	initGitRemote(t, root)
	tagReleased(t, root, "v3.23.2", false)

	d := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Plan: true})
	require.NoError(t, d.CutReleaseBranch(&CutPlan{Derived: "release-v3.23.2-hotfix", Source: TagSource("v3.23.2"), Remote: "origin"}))
	require.False(t, localBranchExists(gitIn(root), "release-v3.23.2-hotfix"))
}
