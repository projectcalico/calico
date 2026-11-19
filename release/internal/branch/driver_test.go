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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/command"
)

// noRefs fails every rev-parse, as in a repo with no matching ref.
func noRefs() *command.Recorder {
	return &command.Recorder{Reply: func(c command.Call) (string, error) {
		if c.Args[0] == "rev-parse" {
			return "", errFake
		}
		return "", nil
	}}
}

func findStep(t *testing.T, steps []Step, name string) Step {
	t.Helper()
	for _, s := range steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("step not found: %s", name)
	return Step{}
}

// stepDriver returns a Driver at repoRoot and the git its steps use. A nil r
// runs real git.
func stepDriver(repoRoot string, r command.CommandRunner, plan bool, skip map[string]bool) (*Driver, command.GitRunner) {
	d := &Driver{RepoRoot: repoRoot, Runner: r, Plan: plan, Skip: skip}
	return d, command.Git(d.runner()).In(repoRoot)
}

func TestRunStepsResumesAndSkips(t *testing.T) {
	var order []string
	steps := []Step{
		{Name: "a", Done: func() (bool, error) { return true, nil }, Do: func() error { order = append(order, "a"); return nil }},  // done -> skipped
		{Name: "b", Done: func() (bool, error) { return false, nil }, Do: func() error { order = append(order, "b"); return nil }}, // runs
		{Name: "c", Done: func() (bool, error) { return false, nil }, Do: func() error { order = append(order, "c"); return nil }}, // skipped by flag
	}
	d, _ := stepDriver("", &command.Recorder{}, false, map[string]bool{"c": true})
	require.NoError(t, d.runSteps(steps))
	require.Equal(t, []string{"b"}, order) // a already done, c skipped

	// plan mode acts on nothing
	order = nil
	plan, _ := stepDriver("", &command.Recorder{}, true, nil)
	require.NoError(t, plan.runSteps(steps))
	require.Empty(t, order)
}

// A skipped step's Done() must not run; it may probe the network.
func TestRunStepsSkipDoesNotProbe(t *testing.T) {
	probed := false
	steps := []Step{
		{Name: "x", Done: func() (bool, error) { probed = true; return false, fmt.Errorf("must not be called") }, Do: func() error { return nil }},
	}
	d, _ := stepDriver("", &command.Recorder{}, false, map[string]bool{"x": true})
	require.NoError(t, d.runSteps(steps), "a skipped step must not run its Done() probe")
	require.False(t, probed, "Done() must not run for a skipped step")
}

func TestCutBranchStepIdempotent(t *testing.T) {
	exists := false
	r := &command.Recorder{Reply: func(c command.Call) (string, error) {
		if c.Args[0] == "rev-parse" && !exists {
			return "", errNoRef
		}
		return "abc123\n", nil
	}}
	p := &CutPlan{Derived: testPrefix + "-v3.33-2", Source: testPrefix + "-v3.33-1"}
	d, dg := stepDriver(t.TempDir(), r, false, nil)
	cut := findStep(t, d.steps(dg, p), "cut-branch")

	done, err := cut.Done()
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, cut.Do())
	require.True(t, ran(r, "branch"))

	exists = true
	done, _ = cut.Done()
	require.True(t, done) // now a no-op
}

// update-derived calls PrepareDerived; plan mode does not.
func TestUpdateDerivedRunsPrepareBranch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "metadata.mk", "MANAGER_BRANCH ?= master\n")

	var events []string
	p := &CutPlan{Derived: testPrefix + "-v3.33"}
	prepare := func(derived string) ([]string, error) {
		written, _, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^MANAGER_BRANCH.*`, Replacement: "MANAGER_BRANCH ?= release-vX"},
		})
		require.NoError(t, err)
		events = append(events, "prepare:"+derived)
		return written, nil
	}

	// plan mode: the step must not act, so the hook does not run and no edit lands.
	planD, planG := stepDriver(root, noRefs(), true, nil)
	planD.PrepareDerived = prepare
	step := findStep(t, planD.steps(planG, p), "update-derived")
	require.NoError(t, planD.runSteps([]Step{step}))
	require.Empty(t, events)
	require.Equal(t, "MANAGER_BRANCH ?= master\n", readFile(t, root, "metadata.mk"))

	// apply mode: the hook runs and its edit lands.
	applyD, applyG := stepDriver(root, noRefs(), false, nil)
	applyD.PrepareDerived = prepare
	step = findStep(t, applyD.steps(applyG, p), "update-derived")
	require.NoError(t, applyD.runSteps([]Step{step}))
	require.Equal(t, []string{"prepare:" + testPrefix + "-v3.33"}, events)
	require.Equal(t, "MANAGER_BRANCH ?= release-vX\n", readFile(t, root, "metadata.mk"))
}

// push-refs Done reports not-done when the remote ref sha differs,
// so a resume re-pushes the stale ref.
func TestPushRefsCheckMatchesRemoteSha(t *testing.T) {
	const localSha = "1111111111111111111111111111111111111111"
	derived := testPrefix + "-v3.33-2"
	tag := "v3.33.0-2.0-" + testSuffix
	p := &CutPlan{Derived: derived, Remote: "origin", TagTargets: []TagTarget{{Branch: derived, DevTag: tag}}}

	// remote ref present but stale -> not done.
	stale := fakeRunner(firstTwo, map[string]string{
		"rev-parse --verify": localSha,
		"ls-remote origin":   "2222222222222222222222222222222222222222\t\n",
	}, nil)
	staleD, staleG := stepDriver(t.TempDir(), stale, false, nil)
	staleD.Publish = true
	check := findStep(t, staleD.steps(staleG, p), "push-refs").Done
	done, err := check()
	require.NoError(t, err)
	require.False(t, done, "a stale remote ref must read as not done")

	// remote ref matches the local sha -> done.
	match := fakeRunner(firstTwo, map[string]string{
		"rev-parse --verify": localSha,
		"ls-remote origin":   localSha + "\t\n",
	}, nil)
	matchD, matchG := stepDriver(t.TempDir(), match, false, nil)
	matchD.Publish = true
	check = findStep(t, matchD.steps(matchG, p), "push-refs").Done
	done, err = check()
	require.NoError(t, err)
	require.True(t, done, "a matching remote ref must read as done")
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	require.NoError(t, err)
	return string(b)
}

// post-push is the last step: runs its hook in apply mode,
// skippable via --skip, and does not run in plan mode.
func TestPostPushStepIsLastSkippableAndPlanned(t *testing.T) {
	var ran int
	p := &CutPlan{Derived: testPrefix + "-v3.33", Remote: "origin"}
	post := func(string) error { ran++; return nil }

	d, g := stepDriver(t.TempDir(), noRefs(), false, nil)
	d.Publish = true // post-push runs its network hook only when publishing
	d.PostDerivedPush = post
	steps := d.steps(g, p)
	require.Equal(t, "post-push", steps[len(steps)-1].Name, "post-push must be the last step")

	step := findStep(t, steps, "post-push")

	// With a hook set, the step is not "done" until it runs.
	done, err := step.Done()
	require.NoError(t, err)
	require.False(t, done)

	// plan mode: does not run.
	planD, planG := stepDriver(t.TempDir(), noRefs(), true, nil)
	planD.PostDerivedPush = post
	require.NoError(t, planD.runSteps([]Step{findStep(t, planD.steps(planG, p), "post-push")}))
	require.Equal(t, 0, ran)

	// skip: does not run.
	skipD, skipG := stepDriver(t.TempDir(), noRefs(), false, map[string]bool{"post-push": true})
	skipD.PostDerivedPush = post
	require.NoError(t, skipD.runSteps([]Step{findStep(t, skipD.steps(skipG, p), "post-push")}))
	require.Equal(t, 0, ran)

	// Publish false still runs the hook, which checks dry-run itself.
	localD, localG := stepDriver(t.TempDir(), noRefs(), false, nil)
	localD.PostDerivedPush = post
	require.NoError(t, localD.runSteps([]Step{findStep(t, localD.steps(localG, p), "post-push")}))
	require.Equal(t, 1, ran)

	// apply: runs the hook once more.
	require.NoError(t, d.runSteps([]Step{step}))
	require.Equal(t, 2, ran)
}

// A ref missing locally makes push-refs report not-done, not error;
// erroring here would abort a --plan or fresh run.
func TestPushRefsCheckMissingLocalRefIsNotDone(t *testing.T) {
	p := &CutPlan{
		Derived:    testPrefix + "-v3.33",
		Remote:     "origin",
		TagTargets: []TagTarget{{Branch: testPrefix + "-v3.33", DevTag: "v3.33.0-" + testSuffix}},
	}
	g := fakeRunner(firstTwo, nil, map[string]error{"rev-parse --verify": errNoRef})
	d := &Driver{Remote: "origin", Publish: true}
	done, err := findStep(t, d.steps(command.Git(g), p), "push-refs").Done()
	require.NoError(t, err, "a missing local ref must not error the check")
	require.False(t, done)
}

func TestPushRefsStep(t *testing.T) {
	derived := testPrefix + "-v3.33"
	p := &CutPlan{Derived: derived, Remote: "origin"}
	for _, tc := range []struct {
		name    string
		publish bool
		dryRun  bool
		want    [][]string
	}{
		{name: "publishes", publish: true, want: [][]string{{"push", "origin", derived}}},
		{name: "dry run checks the push", publish: true, dryRun: true, want: [][]string{{"push", "origin", "--dry-run", derived}}},
		{name: "publish off pushes nothing", dryRun: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &command.Recorder{}
			d := &Driver{Remote: "origin", Publish: tc.publish, DryRun: tc.dryRun}
			if err := findStep(t, d.steps(command.Git(g), p), "push-refs").Do(); err != nil {
				t.Fatalf("push-refs Do() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, gitArgs(g)); diff != "" {
				t.Errorf("git calls (-want +got):\n%s", diff)
			}
		})
	}
}

// A nil PostPush hook makes the step report done, so it never runs.
func TestPostPushNilHookIsDone(t *testing.T) {
	p := &CutPlan{Derived: testPrefix + "-v3.33", Remote: "origin"}
	d, g := stepDriver(t.TempDir(), noRefs(), false, nil)
	post := findStep(t, d.steps(g, p), "post-push")
	done, err := post.Done()
	require.NoError(t, err)
	require.True(t, done, "a nil PostPush hook is already done")
}

// A repo with other values sets them in an init().
var (
	testPrefix = "release"
	testSuffix = "0.dev"
)

func newTestDriver(t *testing.T, d Driver) *Driver {
	t.Helper()
	if d.RepoRoot == "" {
		d.RepoRoot = t.TempDir()
	}
	if d.Remote == "" {
		d.Remote = "origin"
	}
	if d.MainBranch == "" {
		d.MainBranch = "master"
	}
	if d.DevTagIdentifier == "" {
		d.DevTagIdentifier = testSuffix
	}
	if d.ReleaseBranchPrefix == "" {
		d.ReleaseBranchPrefix = testPrefix
	}
	require.NoError(t, d.validate())
	return &d
}

// A cut whose source equals its derived branch is rejected before any git work.
func TestCutReleaseBranchRejectsSourceEqualsDerived(t *testing.T) {
	d := newTestDriver(t, Driver{RepoRoot: t.TempDir()})
	p := &CutPlan{Derived: "release-v3.33", Source: "release-v3.33", Remote: "origin"}
	err := d.CutReleaseBranch(p)
	require.ErrorContains(t, err, "cannot be the same as derived")
}
