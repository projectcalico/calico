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

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/command"
)

var errFake = fmt.Errorf("fake")

// fakeRunner answers each git call from out and errs by key(args). An
// unscripted call returns "" with no error.
func fakeRunner(key func([]string) string, out map[string]string, errs map[string]error) *command.Recorder {
	return &command.Recorder{Reply: func(c command.Call) (string, error) {
		k := key(c.Args)
		return out[k], errs[k]
	}}
}

// firstTwo keys a call by its first two args, so one reply covers every ref.
func firstTwo(args []string) string { return strings.Join(args[:min(2, len(args))], " ") }

func allArgs(args []string) string { return strings.Join(args, " ") }

func gitArgs(r *command.Recorder) [][]string {
	var got [][]string
	for _, c := range r.Calls() {
		got = append(got, c.Args)
	}
	return got
}

func ran(r *command.Recorder, prefix string) bool {
	for _, args := range gitArgs(r) {
		if strings.HasPrefix(strings.Join(args, " "), prefix) {
			return true
		}
	}
	return false
}

func TestLocalBranchExists(t *testing.T) {
	// rev-parse succeeds -> exists
	g := fakeRunner(firstTwo, map[string]string{"rev-parse --verify": "abc\n"}, nil)
	require.True(t, localBranchExists(command.Git(g), testPrefix+"-v3.33-2"))

	// rev-parse errors -> not exists
	g2 := fakeRunner(firstTwo, nil, map[string]error{"rev-parse --verify": errFake})
	require.False(t, localBranchExists(command.Git(g2), "nope"))
}

func TestLocalTagPointsAt(t *testing.T) {
	tagRef := "rev-parse refs/tags/v3.33.0-" + testSuffix
	branchRef := "rev-parse refs/heads/" + testPrefix + "-v3.33"

	// tag and branch resolve to the same sha -> points at.
	g := fakeRunner(firstTwo, map[string]string{tagRef: "abc\n", branchRef: "abc\n"}, nil)
	require.True(t, localTagPointsAt(command.Git(g), "v3.33.0-"+testSuffix, testPrefix+"-v3.33"))

	// tag resolves to a different sha than the branch head -> not.
	g2 := fakeRunner(firstTwo, map[string]string{tagRef: "abc\n", branchRef: "def\n"}, nil)
	require.False(t, localTagPointsAt(command.Git(g2), "v3.33.0-"+testSuffix, testPrefix+"-v3.33"))

	// tag does not exist -> not pointing at.
	g3 := fakeRunner(firstTwo, nil, map[string]error{tagRef: errFake})
	require.False(t, localTagPointsAt(command.Git(g3), "v3.33.0-"+testSuffix, testPrefix+"-v3.33"))
}

func TestRemoteRefMatches(t *testing.T) {
	const sha = "1111111111111111111111111111111111111111"
	ref := testPrefix + "-v3.33-2"

	// present and pointing at the local sha.
	g := fakeRunner(firstTwo, map[string]string{"ls-remote origin": sha + "\trefs/heads/" + ref + "\n"}, nil)
	present, matches, err := remoteRefMatches(command.Git(g), "origin", ref, sha)
	require.NoError(t, err)
	require.True(t, present)
	require.True(t, matches)

	// present but pointing at a different sha.
	other := "2222222222222222222222222222222222222222"
	g2 := fakeRunner(firstTwo, map[string]string{"ls-remote origin": other + "\trefs/heads/" + ref + "\n"}, nil)
	present, matches, err = remoteRefMatches(command.Git(g2), "origin", ref, sha)
	require.NoError(t, err)
	require.True(t, present)
	require.False(t, matches)

	// absent (empty ls-remote output).
	g3 := &command.Recorder{}
	present, matches, err = remoteRefMatches(command.Git(g3), "origin", ref, sha)
	require.NoError(t, err)
	require.False(t, present)
	require.False(t, matches)
}

func TestPushRefs(t *testing.T) {
	branch, tag := testPrefix+"-v3.33-2", "v3.33.0-2.0-"+testSuffix
	for _, tc := range []struct {
		name   string
		dryRun bool
		want   []string
	}{
		{name: "pushes the refs", want: []string{"push", "origin", branch, tag}},
		{name: "dry run", dryRun: true, want: []string{"push", "origin", "--dry-run", branch, tag}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &command.Recorder{}
			if err := pushRefs(command.Git(g), "origin", tc.dryRun, branch, tag); err != nil {
				t.Fatalf("pushRefs() unexpected error: %v", err)
			}
			if diff := cmp.Diff([][]string{tc.want}, gitArgs(g)); diff != "" {
				t.Errorf("git calls (-want +got):\n%s", diff)
			}
		})
	}
}

// fakeGit is a git keyed by the full command.
func fakeGit(out map[string]string, errs map[string]error) command.GitRunner {
	return command.Git(fakeRunner(allArgs, out, errs))
}

func TestCheckBranchCurrent(t *testing.T) {
	src := testPrefix + "-v3.33-1"
	up := "origin/" + src
	const sha = "1111111111111111111111111111111111111111"
	const other = "2222222222222222222222222222222222222222"

	// equalTips scripts local and remote tips for the explicit-remote path.
	equalTips := func(local, remote string) map[string]string {
		return map[string]string{
			"rev-parse " + src:                                              local,
			"rev-parse --verify --quiet " + up:                              remote,
			"rev-parse --abbrev-ref --symbolic-full-name master@{upstream}": "upstream/master",
		}
	}

	const fix = "sync it before cutting, or pass --no-branch-check to cut from the local branch as is"

	t.Run("current: local equals remote", func(t *testing.T) {
		g := fakeGit(equalTips(sha, sha), nil)
		require.NoError(t, checkBranchCurrent(g, src, "origin", true, false, fix))
	})

	t.Run("diverged + branch-check: error carries the recovery hint", func(t *testing.T) {
		g := fakeGit(equalTips(sha, other), nil)
		err := checkBranchCurrent(g, src, "origin", true, false, fix)
		require.ErrorContains(t, err, "not in sync")
		require.ErrorContains(t, err, "--no-branch-check")
	})

	t.Run("diverged + no-branch-check: warn, no error", func(t *testing.T) {
		g := fakeGit(equalTips(sha, other), nil)
		require.NoError(t, checkBranchCurrent(g, src, "origin", false, false, fix))
	})

	t.Run("diverged + report (--plan): no error", func(t *testing.T) {
		g := fakeGit(equalTips(sha, other), nil)
		require.NoError(t, checkBranchCurrent(g, src, "origin", true, true, fix))
	})

	t.Run("main failure uses its own recovery hint, not --no-branch-check", func(t *testing.T) {
		g := fakeGit(equalTips(sha, other), nil)
		err := checkBranchCurrent(g, src, "origin", true, false, "run `git checkout main && git pull` before cutting")
		require.ErrorContains(t, err, "git checkout main && git pull")
		require.NotContains(t, err.Error(), "--no-branch-check")
	})

	t.Run("absent on remote + branch-check: error", func(t *testing.T) {
		// remote tip resolves empty -> not current.
		g := fakeGit(map[string]string{"rev-parse " + src: sha}, nil)
		err := checkBranchCurrent(g, src, "origin", true, false, fix)
		require.ErrorContains(t, err, "not in sync")
	})

	t.Run("empty remote, no configured upstream: error, no fetch", func(t *testing.T) {
		g := fakeRunner(allArgs, nil, map[string]error{
			"rev-parse --abbrev-ref --symbolic-full-name master@{upstream}": errFake,
		})
		err := checkBranchCurrent(command.Git(g), "master", "", true, false, fix)
		require.ErrorContains(t, err, "no valid upstream")
		require.False(t, ran(g, "fetch"), "a missing upstream must fail before fetching")
	})

	t.Run("empty remote reads configured upstream", func(t *testing.T) {
		g := fakeGit(map[string]string{
			"rev-parse --abbrev-ref --symbolic-full-name master@{upstream}": "upstream/master",
			"rev-parse master":                           sha,
			"rev-parse --verify --quiet upstream/master": sha,
		}, nil)
		require.NoError(t, checkBranchCurrent(g, "master", "", true, false, fix))
	})
}

func TestCreateBranch(t *testing.T) {
	g := &command.Recorder{}
	require.NoError(t, createBranch(command.Git(g), testPrefix+"-v3.33-2", testPrefix+"-v3.33-1"))
	require.Equal(t, []string{"branch", testPrefix + "-v3.33-2", testPrefix + "-v3.33-1"}, gitArgs(g)[0])
}

func TestTagWithEmptyCommit(t *testing.T) {
	branch := testPrefix + "-v3.33-2"
	tag := "v3.33.0-2.0-" + testSuffix

	g := &command.Recorder{}
	require.NoError(t, tagWithEmptyCommit(command.Git(g), branch, tag))
	require.Len(t, g.Calls(), 3)
	require.Equal(t, []string{"checkout", branch}, gitArgs(g)[0])
	require.Equal(t, []string{"commit", "--allow-empty", "-m", "Begin development for " + tag}, gitArgs(g)[1])
	require.Equal(t, []string{"tag", "-f", "--no-sign", tag}, gitArgs(g)[2])

	// checkout fails -> wrapped error naming the branch, no further git calls.
	g2 := fakeRunner(firstTwo, nil, map[string]error{"checkout " + branch: errFake})
	err := tagWithEmptyCommit(command.Git(g2), branch, tag)
	require.ErrorContains(t, err, branch)
	require.Len(t, g2.Calls(), 1)
}
