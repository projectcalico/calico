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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

// fakeRunner is a minimal Git for exercising cut-branch idempotency.
type fakeRunner struct {
	branchExists bool
	created      bool
}

func (f *fakeRunner) fn() git {
	return func(args ...string) (string, error) {
		if len(args) == 0 {
			return "", nil
		}
		switch args[0] {
		case "rev-parse":
			if f.branchExists {
				return "abc123\n", nil
			}
			return "", fmt.Errorf("unknown revision")
		case "branch":
			f.created = true
			return "", nil
		case "checkout":
			return "", nil
		}
		return "", nil
	}
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

// stepDriver returns a Driver at repoRoot and the git its steps use.
// A nil g runs against the real repo; otherwise g is a scripted git.
func stepDriver(repoRoot string, g git, plan bool, skip map[string]bool) (*Driver, git) {
	if g == nil {
		g = gitIn(repoRoot)
	}
	return &Driver{RepoRoot: repoRoot, Plan: plan, Skip: skip}, g
}

func TestRunStepsResumesAndSkips(t *testing.T) {
	var order []string
	steps := []Step{
		{Name: "a", Done: func() (bool, error) { return true, nil }, Do: func() error { order = append(order, "a"); return nil }},  // done -> skipped
		{Name: "b", Done: func() (bool, error) { return false, nil }, Do: func() error { order = append(order, "b"); return nil }}, // runs
		{Name: "c", Done: func() (bool, error) { return false, nil }, Do: func() error { order = append(order, "c"); return nil }}, // skipped by flag
	}
	d, _ := stepDriver("", nil, false, map[string]bool{"c": true})
	require.NoError(t, d.runSteps(steps))
	require.Equal(t, []string{"b"}, order) // a already done, c skipped

	// plan mode acts on nothing
	order = nil
	plan, _ := stepDriver("", nil, true, nil)
	require.NoError(t, plan.runSteps(steps))
	require.Empty(t, order)
}

// A skipped step's Done() must not run; it may probe the network.
func TestRunStepsSkipDoesNotProbe(t *testing.T) {
	probed := false
	steps := []Step{
		{Name: "x", Done: func() (bool, error) { probed = true; return false, fmt.Errorf("must not be called") }, Do: func() error { return nil }},
	}
	d, _ := stepDriver("", nil, false, map[string]bool{"x": true})
	require.NoError(t, d.runSteps(steps), "a skipped step must not run its Done() probe")
	require.False(t, probed, "Done() must not run for a skipped step")
}

func TestCutBranchStepIdempotent(t *testing.T) {
	g := &fakeRunner{branchExists: false}
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33-2", Source: utils.ReleaseBranchPrefix() + "-v3.33-1"}
	d, dg := stepDriver(t.TempDir(), g.fn(), false, nil)
	cut := findStep(t, d.steps(dg, p), "cut-branch")

	done, err := cut.Done()
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, cut.Do())
	require.True(t, g.created)

	g.branchExists = true
	done, _ = cut.Done()
	require.True(t, done) // now a no-op
}

// update-derived calls PrepareDerived; plan mode does not.
func TestUpdateDerivedRunsPrepareBranch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "metadata.mk", "OPERATOR_BRANCH ?= master\n")

	var events []string
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33"}
	prepare := func(derived string) ([]string, error) {
		written, _, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^OPERATOR_BRANCH.*`, Replacement: "OPERATOR_BRANCH ?= release-vX"},
		})
		require.NoError(t, err)
		events = append(events, "prepare:"+derived)
		return written, nil
	}

	// plan mode: the step must not act, so the hook does not run and no edit lands.
	planD, planG := stepDriver(root, (&fakeRunner{}).fn(), true, nil)
	planD.PrepareDerived = prepare
	step := findStep(t, planD.steps(planG, p), "update-derived")
	require.NoError(t, planD.runSteps([]Step{step}))
	require.Empty(t, events)
	require.Equal(t, "OPERATOR_BRANCH ?= master\n", readFile(t, root, "metadata.mk"))

	// apply mode: the hook runs and its edit lands.
	applyD, applyG := stepDriver(root, (&fakeRunner{}).fn(), false, nil)
	applyD.PrepareDerived = prepare
	step = findStep(t, applyD.steps(applyG, p), "update-derived")
	require.NoError(t, applyD.runSteps([]Step{step}))
	require.Equal(t, []string{"prepare:" + utils.ReleaseBranchPrefix() + "-v3.33"}, events)
	require.Equal(t, "OPERATOR_BRANCH ?= release-vX\n", readFile(t, root, "metadata.mk"))
}

// push-refs Done reports not-done when the remote ref sha differs,
// so a resume re-pushes the stale ref.
func TestPushRefsCheckMatchesRemoteSha(t *testing.T) {
	const localSha = "1111111111111111111111111111111111111111"
	derived := utils.ReleaseBranchPrefix() + "-v3.33-2"
	tag := "v3.33.0-2.0-" + utils.DevTagSuffix()
	p := &CutPlan{Derived: derived, Remote: "origin", TagTargets: []TagTarget{{Branch: derived, DevTag: tag}}}

	// remote ref present but stale -> not done.
	stale := &gitRec{out: map[string]string{
		"rev-parse --verify": localSha + "\n",
		"ls-remote origin":   "2222222222222222222222222222222222222222\t\n",
	}}
	staleD, staleG := stepDriver(t.TempDir(), stale.fn(), false, nil)
	staleD.Publish = true
	check := findStep(t, staleD.steps(staleG, p), "push-refs").Done
	done, err := check()
	require.NoError(t, err)
	require.False(t, done, "a stale remote ref must read as not done")

	// remote ref matches the local sha -> done.
	match := &gitRec{out: map[string]string{
		"rev-parse --verify": localSha + "\n",
		"ls-remote origin":   localSha + "\t\n",
	}}
	matchD, matchG := stepDriver(t.TempDir(), match.fn(), false, nil)
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

// initGitRepo makes a temp repo with one commit on "master" and returns its root.
func initGitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		_, err := command.GitInDir(root, args...)
		require.NoError(t, err, "git %v", args)
	}
	run("init", "-q", "-b", "master")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	writeFile(t, root, "metadata.mk", "OPERATOR_BRANCH ?= master\n")
	run("add", ".")
	run("commit", "-q", "-m", "initial")
	return root
}

func gitHeadSubject(t *testing.T, root, ref string) string {
	t.Helper()
	out, err := command.GitInDir(root, "log", "-1", "--format=%s", ref)
	require.NoError(t, err)
	return strings.TrimSpace(out)
}

// localCutSteps keeps the cut, edit, and tag steps in order,
// dropping push-refs and post-push (which need a remote).
func localCutSteps(t *testing.T, d *Driver, g git, p *CutPlan) []Step {
	all := d.steps(g, p)
	return []Step{
		findStep(t, all, "cut-branch"),
		findStep(t, all, "update-derived"),
		findStep(t, all, "tag-derived"),
		findStep(t, all, "update-main"),
		findStep(t, all, "tag-main"),
	}
}

// The flow creates the branch with the edit on its head, not an
// empty commit; plan mode commits nothing.
func TestFlowLandsEditOnNewBranch(t *testing.T) {
	root := initGitRepo(t)

	newPlan := func() *CutPlan {
		return &CutPlan{
			Derived: utils.ReleaseBranchPrefix() + "-v3.33",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: utils.ReleaseBranchPrefix() + "-v3.33", DevTag: "v3.33.0-" + utils.DevTagSuffix()},
			},
		}
	}
	prepare := func(string) ([]string, error) {
		written, _, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^OPERATOR_BRANCH.*`, Replacement: "OPERATOR_BRANCH ?= " + utils.ReleaseBranchPrefix() + "-v3.33"},
		})
		return written, err
	}

	// plan mode: nothing is created or committed.
	planD, planG := stepDriver(root, nil, true, nil)
	planD.PrepareDerived = prepare
	require.NoError(t, planD.runSteps(localCutSteps(t, planD, planG, newPlan())))
	require.False(t, localBranchExists(planG, utils.ReleaseBranchPrefix()+"-v3.33"), "plan mode must not create the branch")

	// apply mode: branch is created, edit is committed on its head.
	applyD, applyG := stepDriver(root, nil, false, nil)
	applyD.PrepareDerived = prepare
	require.NoError(t, applyD.runSteps(localCutSteps(t, applyD, applyG, newPlan())))

	require.True(t, localBranchExists(applyG, utils.ReleaseBranchPrefix()+"-v3.33"))

	// The edited file content on the new branch reflects the edit.
	content, err := command.GitInDir(root, "show", utils.ReleaseBranchPrefix()+"-v3.33:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, content, "OPERATOR_BRANCH ?= "+utils.ReleaseBranchPrefix()+"-v3.33")

	// The head is the edits commit, not an empty "Begin development" commit.
	subject := gitHeadSubject(t, root, utils.ReleaseBranchPrefix()+"-v3.33")
	require.Equal(t, "Updates for "+utils.ReleaseBranchPrefix()+"-v3.33 release branch", subject)

	// The edits commit is not empty: it differs from its parent.
	_, err = command.GitInDir(root, "diff", "--quiet", utils.ReleaseBranchPrefix()+"-v3.33~1", utils.ReleaseBranchPrefix()+"-v3.33")
	require.Error(t, err, "the new branch head must contain the edit, not be an empty commit")
}

// A stale local derived tag reads as not-done and tag-derived
// force-moves it onto the branch head.
func TestTagDerivedMovesStaleLocalTag(t *testing.T) {
	root := initGitRepo(t)

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33",
		Source:  "master",
		TagTargets: []TagTarget{
			{Branch: utils.ReleaseBranchPrefix() + "-v3.33", DevTag: "v3.33.0-" + utils.DevTagSuffix()},
		},
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = func(string) ([]string, error) {
		written, _, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^OPERATOR_BRANCH.*`, Replacement: "OPERATOR_BRANCH ?= " + utils.ReleaseBranchPrefix() + "-v3.33"},
		})
		return written, err
	}

	// Create the stale tag on master, at a commit that is not the derived head.
	_, err := command.GitInDir(root, "tag", "--no-sign", "v3.33.0-"+utils.DevTagSuffix())
	require.NoError(t, err)
	staleSha, err := command.GitInDir(root, "rev-parse", "v3.33.0-"+utils.DevTagSuffix()+"^{commit}")
	require.NoError(t, err)

	all := d.steps(g, p)
	cut := findStep(t, all, "cut-branch")
	update := findStep(t, all, "update-derived")
	tagDerived := findStep(t, all, "tag-derived")

	require.NoError(t, cut.Do())
	require.NoError(t, update.Do())

	// The tag exists locally but not at the derived head: Done must be false.
	done, err := tagDerived.Done()
	require.NoError(t, err)
	require.False(t, done, "a local tag at the wrong commit must not read as done")

	require.NoError(t, tagDerived.Do())

	head, err := command.GitInDir(root, "rev-parse", utils.ReleaseBranchPrefix()+"-v3.33")
	require.NoError(t, err)
	movedSha, err := command.GitInDir(root, "rev-parse", "v3.33.0-"+utils.DevTagSuffix()+"^{commit}")
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(head), strings.TrimSpace(movedSha), "the tag must move onto the derived head")
	require.NotEqual(t, strings.TrimSpace(staleSha), strings.TrimSpace(movedSha), "the tag must have actually moved")

	// Idempotent resume: the tag is now on the correct head, so Done is true
	// and re-running Do is harmless.
	done, err = tagDerived.Done()
	require.NoError(t, err)
	require.True(t, done, "once the tag sits on the derived head, the step must read as done")
}

// A cut off main has no derived tag; tag-derived and pushRefs no-op.
func TestFlowMainOnlyPlanNoDerivedTag(t *testing.T) {
	root := srcBumpRepo(t)

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33",
		Source:  "master",
		TagTargets: []TagTarget{
			{Branch: "master", DevTag: "v3.34.0-" + utils.DevTagSuffix()},
		},
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = branchEditPrepare(t, root, utils.ReleaseBranchPrefix()+"-v3.33")

	require.NoError(t, d.runSteps(localCutSteps(t, d, g, p)))

	// The derived branch exists with its edits commit but no dev tag.
	require.True(t, localBranchExists(g, utils.ReleaseBranchPrefix()+"-v3.33"))
	// pushRefs pushes the derived branch and main's tag, but no derived tag.
	require.NotContains(t, d.pushRefs(p), "v3.33.0-"+utils.DevTagSuffix())

	// Main advanced: its dev tag sits on master's head.
	tagged, err := command.GitInDir(root, "rev-parse", "v3.34.0-"+utils.DevTagSuffix()+"^{commit}")
	require.NoError(t, err)
	head, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(head), strings.TrimSpace(tagged))
}

// Every file the PrepareDerived hook returns is committed on the derived branch.
func TestUpdateDerivedCommitsHookReturnedFiles(t *testing.T) {
	root := initGitRepo(t)

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33",
		Source:  "master",
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = func(string) ([]string, error) {
		written, _, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^OPERATOR_BRANCH.*`, Replacement: "OPERATOR_BRANCH ?= " + utils.ReleaseBranchPrefix() + "-v3.33"},
		})
		require.NoError(t, err)
		writeFile(t, root, "hook-file.txt", "written by the hook\n")
		return append(written, "hook-file.txt"), nil
	}

	all := d.steps(g, p)
	local := []Step{findStep(t, all, "cut-branch"), findStep(t, all, "update-derived")}
	require.NoError(t, d.runSteps(local))

	// The hook's extra file is committed on the derived branch head.
	content, err := command.GitInDir(root, "show", utils.ReleaseBranchPrefix()+"-v3.33:hook-file.txt")
	require.NoError(t, err)
	require.Contains(t, content, "written by the hook")

	// The hook's edit landed in the same commit.
	meta, err := command.GitInDir(root, "show", utils.ReleaseBranchPrefix()+"-v3.33:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, meta, "OPERATOR_BRANCH ?= "+utils.ReleaseBranchPrefix()+"-v3.33")
}

// srcBumpRepo makes a temp repo whose metadata.mk carries CALICO_VERSION v3.33.0.
func srcBumpRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		_, err := command.GitInDir(root, args...)
		require.NoError(t, err, "git %v", args)
	}
	run("init", "-q", "-b", "master")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	writeFile(t, root, "metadata.mk", "OPERATOR_BRANCH ?= master\nMANAGER_BRANCH ?= master\nCALICO_VERSION=v3.33.0\n")
	run("add", ".")
	run("commit", "-q", "-m", "initial")
	return root
}

// branchEditPrepare returns a PrepareDerived hook that bumps MANAGER_BRANCH,
// a stand-in for the real derived-branch edit.
func branchEditPrepare(t *testing.T, root, derived string) func(string) ([]string, error) {
	t.Helper()
	return func(string) ([]string, error) {
		written, skipped, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^MANAGER_BRANCH.*`, Replacement: "MANAGER_BRANCH ?= " + derived},
		})
		require.Empty(t, skipped)
		return written, err
	}
}

// bumpMainPrepare returns a PrepareMain hook that bumps CALICO_VERSION on the
// main branch and records the branch it ran on.
func bumpMainPrepare(t *testing.T, root string, ranOn *string) func(string) ([]string, error) {
	t.Helper()
	return func(mainBranch string) ([]string, error) {
		*ranOn = mainBranch
		written, skipped, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^CALICO_VERSION=.*`, Replacement: "CALICO_VERSION=v3.34.0"},
		})
		require.Empty(t, skipped)
		return written, err
	}
}

// PrepareMain bumps CALICO_VERSION on main, not the new branch; main's dev tag
// sits on main's head.
func TestFlowMainBumpAndTag(t *testing.T) {
	root := srcBumpRepo(t)
	var ranOn string

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33-1",
		Source:  "master",
		TagTargets: []TagTarget{
			{Branch: utils.ReleaseBranchPrefix() + "-v3.33-1", DevTag: "v3.33.0-1.0-" + utils.DevTagSuffix()},
			{Branch: "master", DevTag: "v3.34.0-1.0-" + utils.DevTagSuffix()},
		},
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = branchEditPrepare(t, root, utils.ReleaseBranchPrefix()+"-v3.33-1")
	d.PrepareMain = bumpMainPrepare(t, root, &ranOn)

	require.NoError(t, d.runSteps(localCutSteps(t, d, g, p)))

	// PrepareMain ran on main, not the new branch.
	require.Equal(t, "master", ranOn)

	// master's CALICO_VERSION is bumped; the new branch's is not.
	masterMeta, err := command.GitInDir(root, "show", "master:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, masterMeta, "CALICO_VERSION=v3.34.0")

	newMeta, err := command.GitInDir(root, "show", utils.ReleaseBranchPrefix()+"-v3.33-1:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, newMeta, "CALICO_VERSION=v3.33.0", "the main bump must not land on the new branch")
	require.Contains(t, newMeta, "MANAGER_BRANCH ?= "+utils.ReleaseBranchPrefix()+"-v3.33-1", "the new-branch edit must land on the new branch")

	// master's dev tag sits on master's head.
	tagged, err := command.GitInDir(root, "rev-parse", "v3.34.0-1.0-"+utils.DevTagSuffix()+"^{commit}")
	require.NoError(t, err)
	head, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(head), strings.TrimSpace(tagged))
}

// Skipping update-main leaves main's pin unbumped, while tag-main still tags
// master's head with an empty commit.
func TestFlowSkipUpdateMainLeavesPinUnbumped(t *testing.T) {
	root := srcBumpRepo(t)
	var ranOn string

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33-1",
		Source:  "master",
		TagTargets: []TagTarget{
			{Branch: utils.ReleaseBranchPrefix() + "-v3.33-1", DevTag: "v3.33.0-1.0-" + utils.DevTagSuffix()},
			{Branch: "master", DevTag: "v3.34.0-1.0-" + utils.DevTagSuffix()},
		},
	}
	d, g := stepDriver(root, nil, false, map[string]bool{stepUpdateMain: true})
	d.PrepareDerived = branchEditPrepare(t, root, utils.ReleaseBranchPrefix()+"-v3.33-1")
	d.PrepareMain = bumpMainPrepare(t, root, &ranOn)

	require.NoError(t, d.runSteps(localCutSteps(t, d, g, p)))

	// update-main was skipped, so PrepareMain never ran and the pin is unbumped.
	require.Empty(t, ranOn, "update-main must not run when skipped")
	masterMeta, err := command.GitInDir(root, "show", "master:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, masterMeta, "CALICO_VERSION=v3.33.0", "skipping update-main must leave main's pin unbumped")

	// tag-main still tags master's head.
	tagged, err := command.GitInDir(root, "rev-parse", "v3.34.0-1.0-"+utils.DevTagSuffix()+"^{commit}")
	require.NoError(t, err)
	head, err := command.GitInDir(root, "rev-parse", "master")
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(head), strings.TrimSpace(tagged))
}

// With no main tag target, update-main and tag-main no-op even when a
// PrepareMain hook is set.
func TestFlowNoMainTargetSkipsMainSteps(t *testing.T) {
	root := srcBumpRepo(t)
	var ranOn string

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33-1",
		Source:  "master",
		TagTargets: []TagTarget{
			{Branch: utils.ReleaseBranchPrefix() + "-v3.33-1", DevTag: "v3.33.0-1.0-" + utils.DevTagSuffix()},
		},
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = branchEditPrepare(t, root, utils.ReleaseBranchPrefix()+"-v3.33-1")
	d.PrepareMain = bumpMainPrepare(t, root, &ranOn)

	require.NoError(t, d.runSteps(localCutSteps(t, d, g, p)))

	// No main target: PrepareMain must not run and main is untouched.
	require.Empty(t, ranOn, "no main target must not run PrepareMain")
	masterMeta, err := command.GitInDir(root, "show", "master:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, masterMeta, "CALICO_VERSION=v3.33.0", "no main target must leave the pin unbumped")

	// No main dev tag is created.
	_, err = command.GitInDir(root, "rev-parse", "--verify", "--quiet", "refs/tags/v3.34.0-1.0-"+utils.DevTagSuffix())
	require.Error(t, err, "no main target must not create a main dev tag")
}

// A GA master cut with no PrepareSource leaves the source metadata untouched.
func TestFlowNoPrepareSourceForGACut(t *testing.T) {
	root := srcBumpRepo(t)

	p := &CutPlan{
		Derived: utils.ReleaseBranchPrefix() + "-v3.33",
		Source:  "master",
		TagTargets: []TagTarget{
			{Branch: utils.ReleaseBranchPrefix() + "-v3.33", DevTag: "v3.33.0-" + utils.DevTagSuffix()},
		},
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = branchEditPrepare(t, root, utils.ReleaseBranchPrefix()+"-v3.33")
	require.NoError(t, d.runSteps(localCutSteps(t, d, g, p)))

	masterMeta, err := command.GitInDir(root, "show", "master:metadata.mk")
	require.NoError(t, err)
	require.Contains(t, masterMeta, "CALICO_VERSION=v3.33.0", "a GA cut must not bump the source CALICO_VERSION")
}

// post-push is the last step: runs its hook in apply mode,
// skippable via --skip, and does not run in plan mode.
func TestPostPushStepIsLastSkippableAndPlanned(t *testing.T) {
	var ran int
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33", Remote: "origin"}
	post := func(string) error { ran++; return nil }

	d, g := stepDriver(t.TempDir(), (&fakeRunner{}).fn(), false, nil)
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
	planD, planG := stepDriver(t.TempDir(), (&fakeRunner{}).fn(), true, nil)
	planD.PostDerivedPush = post
	require.NoError(t, planD.runSteps([]Step{findStep(t, planD.steps(planG, p), "post-push")}))
	require.Equal(t, 0, ran)

	// skip: does not run.
	skipD, skipG := stepDriver(t.TempDir(), (&fakeRunner{}).fn(), false, map[string]bool{"post-push": true})
	skipD.PostDerivedPush = post
	require.NoError(t, skipD.runSteps([]Step{findStep(t, skipD.steps(skipG, p), "post-push")}))
	require.Equal(t, 0, ran)

	// local run (Publish false): still runs the hook, which honors local mode itself.
	localD, localG := stepDriver(t.TempDir(), (&fakeRunner{}).fn(), false, nil)
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
		Derived:    utils.ReleaseBranchPrefix() + "-v3.33",
		Remote:     "origin",
		TagTargets: []TagTarget{{Branch: utils.ReleaseBranchPrefix() + "-v3.33", DevTag: "v3.33.0-" + utils.DevTagSuffix()}},
	}
	g := &gitRec{errs: map[string]error{"rev-parse --verify": errFake}}
	d := &Driver{Remote: "origin", Publish: true}
	done, err := findStep(t, d.steps(g.fn(), p), "push-refs").Done()
	require.NoError(t, err, "a missing local ref must not error the check")
	require.False(t, done)
}

// A nil PostPush hook makes the step report done, so it never runs.
func TestPostPushNilHookIsDone(t *testing.T) {
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33", Remote: "origin"}
	d, g := stepDriver(t.TempDir(), (&fakeRunner{}).fn(), false, nil)
	post := findStep(t, d.steps(g, p), "post-push")
	done, err := post.Done()
	require.NoError(t, err)
	require.True(t, done, "a nil PostPush hook is already done")
}

// An unrelated pre-staged file left in the index must not enter the cut commit.
func TestStageAndCommitScopedToPaths(t *testing.T) {
	root := initGitRepo(t)
	g := gitIn(root)

	writeFile(t, root, "wanted.txt", "wanted\n")
	writeFile(t, root, "unrelated.txt", "unrelated\n")
	_, err := g("add", "unrelated.txt")
	require.NoError(t, err)

	committed, err := stageAndCommit(g, "cut edit", []string{"wanted.txt"})
	require.NoError(t, err)
	require.True(t, committed)

	files, err := command.GitInDir(root, "show", "--name-only", "--format=", "HEAD")
	require.NoError(t, err)
	require.Contains(t, files, "wanted.txt")
	require.NotContains(t, files, "unrelated.txt", "an unrelated pre-staged file must not enter the cut commit")
}

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
		d.DevTagIdentifier = utils.DevTagSuffix()
	}
	if d.ReleaseBranchPrefix == "" {
		d.ReleaseBranchPrefix = utils.ReleaseBranchPrefix()
	}
	require.NoError(t, d.validate())
	return &d
}

// initGitRemote makes a bare repo to serve as root's "origin", pushes master to
// it, and returns the remote path.
func initGitRemote(t *testing.T, root string) string {
	t.Helper()
	remote := t.TempDir()
	run := func(dir string, args ...string) string {
		out, err := command.GitInDir(dir, args...)
		require.NoError(t, err, "git %v", args)
		return out
	}
	run(remote, "init", "-q", "--bare", "-b", "master")
	run(remote, "config", "tag.gpgsign", "false")
	run(root, "remote", "add", "origin", remote)
	run(root, "push", "-q", "origin", "master")
	return remote
}

// Validate off skips the dirty-tree reject, so a dirty tree does not error.
func TestValidateFreshCutNoValidate(t *testing.T) {
	root := initGitRepo(t)
	initGitRemote(t, root)
	_, err := command.GitInDir(root, "branch", "--set-upstream-to=origin/master", "master")
	require.NoError(t, err)
	writeFile(t, root, "metadata.mk", "OPERATOR_BRANCH ?= dirty\n")
	d := newTestDriver(t, Driver{RepoRoot: root, Validate: false})
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33", Source: "master"}
	require.NoError(t, d.validateFreshCut(gitIn(root), p))
}

// TestValidateFreshCutDirtyTree: a fresh cut with Validate rejects a dirty tree;
// a resume and plan mode do not.
func TestValidateFreshCutDirtyTree(t *testing.T) {
	root := initGitRepo(t)
	// master is current with its upstream so the base check passes and only the
	// dirty-tree gate is under test.
	initGitRemote(t, root)
	_, err := command.GitInDir(root, "branch", "--set-upstream-to=origin/master", "master")
	require.NoError(t, err)
	// Make the tracked tree dirty.
	writeFile(t, root, "metadata.mk", "OPERATOR_BRANCH ?= dirty\n")

	g := gitIn(root)
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33", Source: "master"}

	d := newTestDriver(t, Driver{RepoRoot: root, Validate: true})

	// fresh cut (derived branch absent) + dirty -> rejected.
	err = d.validateFreshCut(g, p)
	require.ErrorContains(t, err, "uncommitted changes")

	// plan mode skips the dirty-tree reject.
	planD := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Plan: true})
	require.NoError(t, planD.validateFreshCut(g, p))

	// --skip is not a resume signal: a fresh cut with --skip still validates.
	skipD := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Skip: map[string]bool{"cut-branch": true}})
	err = skipD.validateFreshCut(g, p)
	require.ErrorContains(t, err, "uncommitted changes", "--skip must not bypass the dirty-tree check on a fresh cut")

	// resume: derived branch exists -> not validated even when dirty.
	_, err = command.GitInDir(root, "branch", p.Derived)
	require.NoError(t, err)
	require.NoError(t, d.validateFreshCut(g, p))
}

// TestValidateFreshCutBaseCheckRunsWithoutValidate checks the base check runs even
// with Validate off: a main behind its upstream is still rejected.
func TestValidateFreshCutBaseCheckRunsWithoutValidate(t *testing.T) {
	root := initGitRepo(t)
	initGitRemote(t, root)
	run := func(args ...string) {
		_, err := command.GitInDir(root, args...)
		require.NoError(t, err, "git %v", args)
	}
	// Push an extra commit to origin, then reset local master back so it is behind
	// its upstream.
	run("branch", "--set-upstream-to=origin/master", "master")
	run("commit", "-q", "--allow-empty", "-m", "ahead")
	run("push", "-q", "origin", "master")
	run("reset", "-q", "--hard", "HEAD~1")

	d := newTestDriver(t, Driver{RepoRoot: root, Validate: false})
	p := &CutPlan{Derived: utils.ReleaseBranchPrefix() + "-v3.33", Source: "master"}
	err := d.validateFreshCut(gitIn(root), p)
	require.ErrorContains(t, err, "not in sync", "the base check must run even with --no-validation")
}

// A cut whose source equals its derived branch is rejected before any git work.
func TestCutReleaseBranchRejectsSourceEqualsDerived(t *testing.T) {
	d := newTestDriver(t, Driver{RepoRoot: t.TempDir()})
	p := &CutPlan{Derived: "release-v3.33", Source: "release-v3.33", Remote: "origin"}
	err := d.CutReleaseBranch(p)
	require.ErrorContains(t, err, "cannot be the same as derived")
}

// A resume re-cuts the derived branch from source when source advanced, so new
// source commits are picked up; an unchanged source leaves the branch in place.
func TestUpdateDerivedResetsWhenSourceAdvanced(t *testing.T) {
	root := initGitRepo(t)
	derived := utils.ReleaseBranchPrefix() + "-v3.33"
	p := &CutPlan{Derived: derived, Source: "master"}
	prepare := func(string) ([]string, error) {
		written, _, err := ApplyEdits(root, []Edit{
			{File: "metadata.mk", Pattern: `^OPERATOR_BRANCH.*`, Replacement: "OPERATOR_BRANCH ?= " + derived},
		})
		return written, err
	}
	d, g := stepDriver(root, nil, false, nil)
	d.PrepareDerived = prepare

	// First cut: create derived off master and apply the edit.
	all := d.steps(g, p)
	require.NoError(t, d.runSteps([]Step{findStep(t, all, "cut-branch"), findStep(t, all, "update-derived")}))

	// Advance master with a new commit the derived branch does not have.
	_, err := command.GitInDir(root, "checkout", "-q", "master")
	require.NoError(t, err)
	writeFile(t, root, "new-on-master.txt", "added after the cut\n")
	_, err = command.GitInDir(root, "add", ".")
	require.NoError(t, err)
	_, err = command.GitInDir(root, "commit", "-q", "-m", "advance master")
	require.NoError(t, err)

	// Resume update-derived: it must re-cut derived from the advanced master.
	require.NoError(t, d.runSteps([]Step{findStep(t, d.steps(g, p), "update-derived")}))

	// The derived branch now contains master's new file, and still has the edit.
	content, err := command.GitInDir(root, "show", derived+":new-on-master.txt")
	require.NoError(t, err)
	require.Contains(t, content, "added after the cut", "derived must pick up the advanced source commit")
	meta, err := command.GitInDir(root, "show", derived+":metadata.mk")
	require.NoError(t, err)
	require.Contains(t, meta, "OPERATOR_BRANCH ?= "+derived, "the edit must be re-applied after the reset")
}
