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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/utils"
)

var errFake = fmt.Errorf("fake")

// gitRec records args and returns scripted outputs keyed by the first two args.
type gitRec struct {
	out  map[string]string
	errs map[string]error
	runs [][]string
}

func (r *gitRec) fn() git {
	return func(args ...string) (string, error) {
		r.runs = append(r.runs, args)
		key := strings.Join(args[:min(2, len(args))], " ")
		return r.out[key], r.errs[key]
	}
}

func TestLocalBranchExists(t *testing.T) {
	// rev-parse succeeds -> exists
	g := &gitRec{out: map[string]string{"rev-parse --verify": "abc\n"}}
	require.True(t, localBranchExists(g.fn(), utils.ReleaseBranchPrefix()+"-v3.33-2"))

	// rev-parse errors -> not exists
	g2 := &gitRec{errs: map[string]error{"rev-parse --verify": errFake}}
	require.False(t, localBranchExists(g2.fn(), "nope"))
}

func TestLocalTagPointsAt(t *testing.T) {
	tagRef := "rev-parse refs/tags/v3.33.0-" + utils.DevTagSuffix()
	branchRef := "rev-parse refs/heads/" + utils.ReleaseBranchPrefix() + "-v3.33"

	// tag and branch resolve to the same sha -> points at.
	g := &gitRec{out: map[string]string{tagRef: "abc\n", branchRef: "abc\n"}}
	require.True(t, localTagPointsAt(g.fn(), "v3.33.0-"+utils.DevTagSuffix(), utils.ReleaseBranchPrefix()+"-v3.33"))

	// tag resolves to a different sha than the branch head -> not.
	g2 := &gitRec{out: map[string]string{tagRef: "abc\n", branchRef: "def\n"}}
	require.False(t, localTagPointsAt(g2.fn(), "v3.33.0-"+utils.DevTagSuffix(), utils.ReleaseBranchPrefix()+"-v3.33"))

	// tag does not exist -> not pointing at.
	g3 := &gitRec{errs: map[string]error{tagRef: errFake}}
	require.False(t, localTagPointsAt(g3.fn(), "v3.33.0-"+utils.DevTagSuffix(), utils.ReleaseBranchPrefix()+"-v3.33"))
}

func TestRemoteRefMatches(t *testing.T) {
	const sha = "1111111111111111111111111111111111111111"
	ref := utils.ReleaseBranchPrefix() + "-v3.33-2"

	// present and pointing at the local sha.
	g := &gitRec{out: map[string]string{"ls-remote origin": sha + "\trefs/heads/" + ref + "\n"}}
	present, matches, err := remoteRefMatches(g.fn(), "origin", ref, sha)
	require.NoError(t, err)
	require.True(t, present)
	require.True(t, matches)

	// present but pointing at a different sha.
	other := "2222222222222222222222222222222222222222"
	g2 := &gitRec{out: map[string]string{"ls-remote origin": other + "\trefs/heads/" + ref + "\n"}}
	present, matches, err = remoteRefMatches(g2.fn(), "origin", ref, sha)
	require.NoError(t, err)
	require.True(t, present)
	require.False(t, matches)

	// absent (empty ls-remote output).
	g3 := &gitRec{}
	present, matches, err = remoteRefMatches(g3.fn(), "origin", ref, sha)
	require.NoError(t, err)
	require.False(t, present)
	require.False(t, matches)
}

func TestPushRefs(t *testing.T) {
	g := &gitRec{}
	require.NoError(t, pushRefs(g.fn(), "origin", utils.ReleaseBranchPrefix()+"-v3.33-2", "v3.33.0-2.0-"+utils.DevTagSuffix()))
	require.Equal(t, []string{"push", "origin", utils.ReleaseBranchPrefix() + "-v3.33-2", "v3.33.0-2.0-" + utils.DevTagSuffix()}, g.runs[0])
}

// gitScriptRec matches scripted responses by the full joined command and
// records every call. An unscripted command returns "" with no error.
type gitScriptRec struct {
	out  map[string]string
	errs map[string]error
	runs [][]string
}

func (r *gitScriptRec) fn() git {
	return func(args ...string) (string, error) {
		r.runs = append(r.runs, args)
		key := strings.Join(args, " ")
		return r.out[key], r.errs[key]
	}
}

func (r *gitScriptRec) ranPrefix(prefix string) bool {
	for _, run := range r.runs {
		if strings.HasPrefix(strings.Join(run, " "), prefix) {
			return true
		}
	}
	return false
}

// gitScript is a non-recording git func keyed by full joined command;
// unscripted commands return "" with no error.
func gitScript(out map[string]string, errs map[string]error) git {
	return (&gitScriptRec{out: out, errs: errs}).fn()
}

func TestCheckBranchCurrent(t *testing.T) {
	src := utils.ReleaseBranchPrefix() + "-v3.33-1"
	up := "origin/" + src
	const sha = "1111111111111111111111111111111111111111"
	const other = "2222222222222222222222222222222222222222"

	// equalTips scripts local and remote tips for the explicit-remote path.
	equalTips := func(local, remote string) map[string]string {
		return map[string]string{
			"rev-parse " + src:                 local,
			"rev-parse --verify --quiet " + up: remote,
			"rev-parse --abbrev-ref --symbolic-full-name master@{upstream}": "upstream/master",
		}
	}

	const fix = "sync it before cutting, or pass --no-branch-check to cut from the local branch as is"

	t.Run("current: local equals remote", func(t *testing.T) {
		g := gitScript(equalTips(sha, sha), nil)
		require.NoError(t, checkBranchCurrent(g, src, "origin", true, false, fix))
	})

	t.Run("diverged + branch-check: error carries the recovery hint", func(t *testing.T) {
		g := gitScript(equalTips(sha, other), nil)
		err := checkBranchCurrent(g, src, "origin", true, false, fix)
		require.ErrorContains(t, err, "not in sync")
		require.ErrorContains(t, err, "--no-branch-check")
	})

	t.Run("diverged + no-branch-check: warn, no error", func(t *testing.T) {
		g := gitScript(equalTips(sha, other), nil)
		require.NoError(t, checkBranchCurrent(g, src, "origin", false, false, fix))
	})

	t.Run("diverged + report (--plan): no error", func(t *testing.T) {
		g := gitScript(equalTips(sha, other), nil)
		require.NoError(t, checkBranchCurrent(g, src, "origin", true, true, fix))
	})

	t.Run("main failure uses its own recovery hint, not --no-branch-check", func(t *testing.T) {
		g := gitScript(equalTips(sha, other), nil)
		err := checkBranchCurrent(g, src, "origin", true, false, "run `git checkout main && git pull` before cutting")
		require.ErrorContains(t, err, "git checkout main && git pull")
		require.NotContains(t, err.Error(), "--no-branch-check")
	})

	t.Run("absent on remote + branch-check: error", func(t *testing.T) {
		// remote tip resolves empty -> not current.
		g := gitScript(map[string]string{"rev-parse " + src: sha}, nil)
		err := checkBranchCurrent(g, src, "origin", true, false, fix)
		require.ErrorContains(t, err, "not in sync")
	})

	t.Run("empty remote, no configured upstream: error, no fetch", func(t *testing.T) {
		g := &gitScriptRec{errs: map[string]error{
			"rev-parse --abbrev-ref --symbolic-full-name master@{upstream}": errFake,
		}}
		err := checkBranchCurrent(g.fn(), "master", "", true, false, fix)
		require.ErrorContains(t, err, "no valid upstream")
		require.False(t, g.ranPrefix("fetch"), "a missing upstream must fail before fetching")
	})

	t.Run("empty remote reads configured upstream", func(t *testing.T) {
		g := gitScript(map[string]string{
			"rev-parse --abbrev-ref --symbolic-full-name master@{upstream}": "upstream/master",
			"rev-parse master":                           sha,
			"rev-parse --verify --quiet upstream/master": sha,
		}, nil)
		require.NoError(t, checkBranchCurrent(g, "master", "", true, false, fix))
	})
}

func TestCreateBranch(t *testing.T) {
	g := &gitRec{}
	require.NoError(t, createBranch(g.fn(), utils.ReleaseBranchPrefix()+"-v3.33-2", utils.ReleaseBranchPrefix()+"-v3.33-1"))
	require.Equal(t, []string{"branch", utils.ReleaseBranchPrefix() + "-v3.33-2", utils.ReleaseBranchPrefix() + "-v3.33-1"}, g.runs[0])
}

func TestTagWithEmptyCommit(t *testing.T) {
	branch := utils.ReleaseBranchPrefix() + "-v3.33-2"
	tag := "v3.33.0-2.0-" + utils.DevTagSuffix()

	g := &gitRec{}
	require.NoError(t, tagWithEmptyCommit(g.fn(), branch, tag))
	require.Len(t, g.runs, 3)
	require.Equal(t, []string{"checkout", branch}, g.runs[0])
	require.Equal(t, []string{"commit", "--allow-empty", "-m", "Begin development for " + tag}, g.runs[1])
	require.Equal(t, []string{"tag", "-f", "--no-sign", tag}, g.runs[2])

	// checkout fails -> wrapped error naming the branch, no further git calls.
	g2 := &gitRec{errs: map[string]error{"checkout " + branch: errFake}}
	err := tagWithEmptyCommit(g2.fn(), branch, tag)
	require.ErrorContains(t, err, branch)
	require.Len(t, g2.runs, 1)
}
