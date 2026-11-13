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
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/command"
)

// A worktree build exports GIT_DIR, which would point every temp repo at the
// real checkout.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("GIT_DIR")
	_ = os.Unsetenv("GIT_WORK_TREE")
	os.Exit(m.Run())
}

func realGit(root string) command.GitRunner {
	return command.Git(command.RealRunner).In(root)
}

func branchExists(t *testing.T, g command.GitRunner, name string) bool {
	t.Helper()
	exists, err := localBranchExists(g, name)
	if err != nil {
		t.Fatal(err)
	}
	return exists
}

// initGitRepo makes a temp repo with one commit on "master" and returns its root.
func initGitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		_, err := realGit(root).Run(args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
	run("init", "-q", "-b", "master")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	writeFile(t, root, "metadata.mk", "MANAGER_BRANCH ?= master\n")
	run("add", ".")
	run("commit", "-q", "-m", "initial")
	return root
}

func gitHeadSubject(t *testing.T, root, ref string) string {
	t.Helper()
	out, err := realGit(root).Run("log", "-1", "--format=%s", ref)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// localCutSteps keeps the cut, edit, and tag steps in order,
// dropping push-refs and post-push (which need a remote).
func localCutSteps(t *testing.T, d *Driver, g command.GitRunner, p *CutPlan) []Step {
	all := d.steps(g, p)
	return []Step{
		findStep(t, all, "cut-branch"),
		findStep(t, all, "update-derived"),
		findStep(t, all, "tag-derived"),
		findStep(t, all, "update-main"),
		findStep(t, all, "tag-main"),
	}
}

func TestCutReleaseBranchFlow(t *testing.T) {
	// The flow creates the branch with the edit on its head, not an
	// empty commit; plan mode commits nothing.
	t.Run("lands the edit on the new branch", func(t *testing.T) {
		root := initGitRepo(t)

		newPlan := func() *CutPlan {
			return &CutPlan{
				Derived: testPrefix + "-v3.33",
				Source:  "master",
				TagTargets: []TagTarget{
					{Branch: testPrefix + "-v3.33", DevTag: "v3.33.0-" + testSuffix},
				},
			}
		}
		prepare := func(string) ([]string, error) {
			written, _, err := ApplyEdits(root, []Edit{
				{File: "metadata.mk", Pattern: `^MANAGER_BRANCH.*`, Replacement: "MANAGER_BRANCH ?= " + testPrefix + "-v3.33"},
			})
			return written, err
		}

		// plan mode: nothing is created or committed.
		planD, planG := stepDriver(root, nil, true, nil)
		planD.PrepareDerived = prepare
		if err := planD.runSteps(localCutSteps(t, planD, planG, newPlan())); err != nil {
			t.Fatal(err)
		}
		if branchExists(t, planG, testPrefix+"-v3.33") {
			t.Fatalf("plan mode must not create the branch")
		}

		// apply mode: branch is created, edit is committed on its head.
		applyD, applyG := stepDriver(root, nil, false, nil)
		applyD.PrepareDerived = prepare
		if err := applyD.runSteps(localCutSteps(t, applyD, applyG, newPlan())); err != nil {
			t.Fatal(err)
		}

		if !branchExists(t, applyG, testPrefix+"-v3.33") {
			t.Fatal("localBranchExists(applyG, testPrefix+\"-v3.33\") = false")
		}

		// The edited file content on the new branch reflects the edit.
		content, err := realGit(root).Run("show", testPrefix+"-v3.33:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(content, "MANAGER_BRANCH ?= "+testPrefix+"-v3.33") {
			t.Fatalf("%q missing %q", content, "MANAGER_BRANCH ?= "+testPrefix+"-v3.33")
		}

		// The head is the edits commit, not an empty "Begin development" commit.
		subject := gitHeadSubject(t, root, testPrefix+"-v3.33")
		if diff := cmp.Diff("Updates for "+testPrefix+"-v3.33 release branch", subject); diff != "" {
			t.Fatalf("subject mismatch (-want +got):\n%s", diff)
		}

		// The edits commit is not empty: it differs from its parent.
		_, err = realGit(root).Run("diff", "--quiet", testPrefix+"-v3.33~1", testPrefix+"-v3.33")
		if err == nil {
			t.Fatalf("the new branch head must contain the edit, not be an empty commit")
		}
	})

	// A cut off main has no derived tag; tag-derived and pushRefs no-op.
	t.Run("a main-only cut has no derived tag", func(t *testing.T) {
		root := srcBumpRepo(t)

		p := &CutPlan{
			Derived: testPrefix + "-v3.33",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: "master", DevTag: "v3.34.0-" + testSuffix},
			},
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = branchEditPrepare(t, root, testPrefix+"-v3.33")

		if err := d.runSteps(localCutSteps(t, d, g, p)); err != nil {
			t.Fatal(err)
		}

		// The derived branch exists with its edits commit but no dev tag.
		if !branchExists(t, g, testPrefix+"-v3.33") {
			t.Fatal("localBranchExists(g, testPrefix+\"-v3.33\") = false")
		}
		// pushRefs pushes the derived branch and main's tag, but no derived tag.
		if slices.Contains(d.pushRefs(p), "v3.33.0-"+testSuffix) {
			t.Fatalf("%q has %q", d.pushRefs(p), "v3.33.0-"+testSuffix)
		}

		// Main advanced: its dev tag sits on master's head.
		tagged, err := realGit(root).Run("rev-parse", "v3.34.0-"+testSuffix+"^{commit}")
		if err != nil {
			t.Fatal(err)
		}
		head, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(strings.TrimSpace(head), strings.TrimSpace(tagged)); diff != "" {
			t.Fatalf("strings.TrimSpace(tagged) mismatch (-want +got):\n%s", diff)
		}
	})

	// PrepareMain bumps CALICO_VERSION on main, not the new branch; main's dev tag
	// sits on main's head.
	t.Run("bumps and tags main", func(t *testing.T) {
		root := srcBumpRepo(t)
		var ranOn string

		p := &CutPlan{
			Derived: testPrefix + "-v3.33-1",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: testPrefix + "-v3.33-1", DevTag: "v3.33.0-1.0-" + testSuffix},
				{Branch: "master", DevTag: "v3.34.0-1.0-" + testSuffix},
			},
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = branchEditPrepare(t, root, testPrefix+"-v3.33-1")
		d.PrepareMain = bumpMainPrepare(t, root, &ranOn)

		if err := d.runSteps(localCutSteps(t, d, g, p)); err != nil {
			t.Fatal(err)
		}

		// PrepareMain ran on main, not the new branch.
		if diff := cmp.Diff("master", ranOn); diff != "" {
			t.Fatalf("ranOn mismatch (-want +got):\n%s", diff)
		}

		// master's CALICO_VERSION is bumped; the new branch's is not.
		masterMeta, err := realGit(root).Run("show", "master:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(masterMeta, "CALICO_VERSION=v3.34.0") {
			t.Fatalf("%q missing %q", masterMeta, "CALICO_VERSION=v3.34.0")
		}

		newMeta, err := realGit(root).Run("show", testPrefix+"-v3.33-1:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(newMeta, "CALICO_VERSION=v3.33.0") {
			t.Fatalf("the main bump must not land on the new branch: %q missing %q", newMeta, "CALICO_VERSION=v3.33.0")
		}
		if !strings.Contains(newMeta, "MANAGER_BRANCH ?= "+testPrefix+"-v3.33-1") {
			t.Fatalf("the new-branch edit must land on the new branch: %q missing %q", newMeta, "MANAGER_BRANCH ?= "+testPrefix+"-v3.33-1")
		}

		// master's dev tag sits on master's head.
		tagged, err := realGit(root).Run("rev-parse", "v3.34.0-1.0-"+testSuffix+"^{commit}")
		if err != nil {
			t.Fatal(err)
		}
		head, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(strings.TrimSpace(head), strings.TrimSpace(tagged)); diff != "" {
			t.Fatalf("strings.TrimSpace(tagged) mismatch (-want +got):\n%s", diff)
		}
	})

	// Skipping update-main leaves main's pin unbumped, while tag-main still tags
	// master's head with an empty commit.
	t.Run("skipping update-main leaves the pin unbumped", func(t *testing.T) {
		root := srcBumpRepo(t)
		var ranOn string

		p := &CutPlan{
			Derived: testPrefix + "-v3.33-1",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: testPrefix + "-v3.33-1", DevTag: "v3.33.0-1.0-" + testSuffix},
				{Branch: "master", DevTag: "v3.34.0-1.0-" + testSuffix},
			},
		}
		d, g := stepDriver(root, nil, false, map[string]bool{stepUpdateMain: true})
		d.PrepareDerived = branchEditPrepare(t, root, testPrefix+"-v3.33-1")
		d.PrepareMain = bumpMainPrepare(t, root, &ranOn)

		if err := d.runSteps(localCutSteps(t, d, g, p)); err != nil {
			t.Fatal(err)
		}

		// update-main was skipped, so PrepareMain never ran and the pin is unbumped.
		if len(ranOn) != 0 {
			t.Fatalf("update-main must not run when skipped: %q", ranOn)
		}
		masterMeta, err := realGit(root).Run("show", "master:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(masterMeta, "CALICO_VERSION=v3.33.0") {
			t.Fatalf("skipping update-main must leave main's pin unbumped: %q missing %q", masterMeta, "CALICO_VERSION=v3.33.0")
		}

		// tag-main still tags master's head.
		tagged, err := realGit(root).Run("rev-parse", "v3.34.0-1.0-"+testSuffix+"^{commit}")
		if err != nil {
			t.Fatal(err)
		}
		head, err := realGit(root).Run("rev-parse", "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(strings.TrimSpace(head), strings.TrimSpace(tagged)); diff != "" {
			t.Fatalf("strings.TrimSpace(tagged) mismatch (-want +got):\n%s", diff)
		}
	})

	// With no main tag target, update-main and tag-main no-op even when a
	// PrepareMain hook is set.
	t.Run("no main target skips the main steps", func(t *testing.T) {
		root := srcBumpRepo(t)
		var ranOn string

		p := &CutPlan{
			Derived: testPrefix + "-v3.33-1",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: testPrefix + "-v3.33-1", DevTag: "v3.33.0-1.0-" + testSuffix},
			},
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = branchEditPrepare(t, root, testPrefix+"-v3.33-1")
		d.PrepareMain = bumpMainPrepare(t, root, &ranOn)

		if err := d.runSteps(localCutSteps(t, d, g, p)); err != nil {
			t.Fatal(err)
		}

		// No main target: PrepareMain must not run and main is untouched.
		if len(ranOn) != 0 {
			t.Fatalf("no main target must not run PrepareMain: %q", ranOn)
		}
		masterMeta, err := realGit(root).Run("show", "master:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(masterMeta, "CALICO_VERSION=v3.33.0") {
			t.Fatalf("no main target must leave the pin unbumped: %q missing %q", masterMeta, "CALICO_VERSION=v3.33.0")
		}

		// No main dev tag is created.
		_, err = realGit(root).Run("rev-parse", "--verify", "--quiet", "refs/tags/v3.34.0-1.0-"+testSuffix)
		if err == nil {
			t.Fatalf("no main target must not create a main dev tag")
		}
	})

	// A GA master cut with no PrepareSource leaves the source metadata untouched.
	t.Run("a GA cut leaves the source metadata", func(t *testing.T) {
		root := srcBumpRepo(t)

		p := &CutPlan{
			Derived: testPrefix + "-v3.33",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: testPrefix + "-v3.33", DevTag: "v3.33.0-" + testSuffix},
			},
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = branchEditPrepare(t, root, testPrefix+"-v3.33")
		if err := d.runSteps(localCutSteps(t, d, g, p)); err != nil {
			t.Fatal(err)
		}

		masterMeta, err := realGit(root).Run("show", "master:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(masterMeta, "CALICO_VERSION=v3.33.0") {
			t.Fatalf("a GA cut must not bump the source CALICO_VERSION: %q missing %q", masterMeta, "CALICO_VERSION=v3.33.0")
		}
	})

	// An unrelated pre-staged file left in the index must not enter the cut commit.
	t.Run("commits only the given paths", func(t *testing.T) {
		root := initGitRepo(t)
		g := realGit(root)

		writeFile(t, root, "wanted.txt", "wanted\n")
		writeFile(t, root, "unrelated.txt", "unrelated\n")
		_, err := g.Run("add", "unrelated.txt")
		if err != nil {
			t.Fatal(err)
		}

		committed, err := stageAndCommit(g, "cut edit", []string{"wanted.txt"})
		if err != nil {
			t.Fatal(err)
		}
		if !committed {
			t.Fatal("committed = false")
		}

		files, err := realGit(root).Run("show", "--name-only", "--format=", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(files, "wanted.txt") {
			t.Fatalf("%q missing %q", files, "wanted.txt")
		}
		if strings.Contains(files, "unrelated.txt") {
			t.Fatalf("an unrelated pre-staged file must not enter the cut commit: %q has %q", files, "unrelated.txt")
		}
	})
}

func TestDerived(t *testing.T) {
	// Every file the PrepareDerived hook returns is committed on the derived branch.
	t.Run("commits the files the hook returns", func(t *testing.T) {
		root := initGitRepo(t)

		p := &CutPlan{
			Derived: testPrefix + "-v3.33",
			Source:  "master",
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = func(string) ([]string, error) {
			written, _, err := ApplyEdits(root, []Edit{
				{File: "metadata.mk", Pattern: `^MANAGER_BRANCH.*`, Replacement: "MANAGER_BRANCH ?= " + testPrefix + "-v3.33"},
			})
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, root, "hook-file.txt", "written by the hook\n")
			return append(written, "hook-file.txt"), nil
		}

		all := d.steps(g, p)
		local := []Step{findStep(t, all, "cut-branch"), findStep(t, all, "update-derived")}
		if err := d.runSteps(local); err != nil {
			t.Fatal(err)
		}

		// The hook's extra file is committed on the derived branch head.
		content, err := realGit(root).Run("show", testPrefix+"-v3.33:hook-file.txt")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(content, "written by the hook") {
			t.Fatalf("%q missing %q", content, "written by the hook")
		}

		// The hook's edit landed in the same commit.
		meta, err := realGit(root).Run("show", testPrefix+"-v3.33:metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(meta, "MANAGER_BRANCH ?= "+testPrefix+"-v3.33") {
			t.Fatalf("%q missing %q", meta, "MANAGER_BRANCH ?= "+testPrefix+"-v3.33")
		}
	})

	// A resume re-cuts the derived branch from source when source advanced, so new
	// source commits are picked up; an unchanged source leaves the branch in place.
	t.Run("resets when the source advanced", func(t *testing.T) {
		root := initGitRepo(t)
		derived := testPrefix + "-v3.33"
		p := &CutPlan{Derived: derived, Source: "master"}
		prepare := func(string) ([]string, error) {
			written, _, err := ApplyEdits(root, []Edit{
				{File: "metadata.mk", Pattern: `^MANAGER_BRANCH.*`, Replacement: "MANAGER_BRANCH ?= " + derived},
			})
			return written, err
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = prepare

		// First cut: create derived off master and apply the edit.
		all := d.steps(g, p)
		if err := d.runSteps([]Step{findStep(t, all, "cut-branch"), findStep(t, all, "update-derived")}); err != nil {
			t.Fatal(err)
		}

		// Advance master with a new commit the derived branch does not have.
		_, err := realGit(root).Run("checkout", "-q", "master")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, root, "new-on-master.txt", "added after the cut\n")
		_, err = realGit(root).Run("add", ".")
		if err != nil {
			t.Fatal(err)
		}
		_, err = realGit(root).Run("commit", "-q", "-m", "advance master")
		if err != nil {
			t.Fatal(err)
		}

		// Resume update-derived: it must re-cut derived from the advanced master.
		if err := d.runSteps([]Step{findStep(t, d.steps(g, p), "update-derived")}); err != nil {
			t.Fatal(err)
		}

		// The derived branch now contains master's new file, and still has the edit.
		content, err := realGit(root).Run("show", derived+":new-on-master.txt")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(content, "added after the cut") {
			t.Fatalf("derived must pick up the advanced source commit: %q missing %q", content, "added after the cut")
		}
		meta, err := realGit(root).Run("show", derived+":metadata.mk")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(meta, "MANAGER_BRANCH ?= "+derived) {
			t.Fatalf("the edit must be re-applied after the reset: %q missing %q", meta, "MANAGER_BRANCH ?= "+derived)
		}
	})

	// A stale local derived tag reads as not-done and tag-derived
	// force-moves it onto the branch head.
	t.Run("moves a stale local tag", func(t *testing.T) {
		root := initGitRepo(t)

		p := &CutPlan{
			Derived: testPrefix + "-v3.33",
			Source:  "master",
			TagTargets: []TagTarget{
				{Branch: testPrefix + "-v3.33", DevTag: "v3.33.0-" + testSuffix},
			},
		}
		d, g := stepDriver(root, nil, false, nil)
		d.PrepareDerived = func(string) ([]string, error) {
			written, _, err := ApplyEdits(root, []Edit{
				{File: "metadata.mk", Pattern: `^MANAGER_BRANCH.*`, Replacement: "MANAGER_BRANCH ?= " + testPrefix + "-v3.33"},
			})
			return written, err
		}

		// Create the stale tag on master, at a commit that is not the derived head.
		_, err := realGit(root).Run("tag", "--no-sign", "v3.33.0-"+testSuffix)
		if err != nil {
			t.Fatal(err)
		}
		staleSha, err := realGit(root).Run("rev-parse", "v3.33.0-"+testSuffix+"^{commit}")
		if err != nil {
			t.Fatal(err)
		}

		all := d.steps(g, p)
		cut := findStep(t, all, "cut-branch")
		update := findStep(t, all, "update-derived")
		tagDerived := findStep(t, all, "tag-derived")

		if err := cut.Do(); err != nil {
			t.Fatal(err)
		}
		if err := update.Do(); err != nil {
			t.Fatal(err)
		}

		// The tag exists locally but not at the derived head: Done must be false.
		done, err := tagDerived.Done()
		if err != nil {
			t.Fatal(err)
		}
		if done {
			t.Fatalf("a local tag at the wrong commit must not read as done")
		}

		if err := tagDerived.Do(); err != nil {
			t.Fatal(err)
		}

		head, err := realGit(root).Run("rev-parse", testPrefix+"-v3.33")
		if err != nil {
			t.Fatal(err)
		}
		movedSha, err := realGit(root).Run("rev-parse", "v3.33.0-"+testSuffix+"^{commit}")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(strings.TrimSpace(head), strings.TrimSpace(movedSha)); diff != "" {
			t.Fatalf("the tag must move onto the derived head (-want +got):\n%s", diff)
		}
		if cmp.Equal(strings.TrimSpace(staleSha), strings.TrimSpace(movedSha)) {
			t.Fatalf("the tag must have actually moved: both %q", strings.TrimSpace(staleSha))
		}

		// Idempotent resume: the tag is now on the correct head, so Done is true
		// and re-running Do is harmless.
		done, err = tagDerived.Done()
		if err != nil {
			t.Fatal(err)
		}
		if !done {
			t.Fatalf("once the tag sits on the derived head, the step must read as done")
		}
	})
}

// srcBumpRepo makes a temp repo whose metadata.mk carries CALICO_VERSION v3.33.0.
func srcBumpRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		_, err := realGit(root).Run(args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
	run("init", "-q", "-b", "master")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	writeFile(t, root, "metadata.mk", "MANAGER_BRANCH ?= master\nCALICO_VERSION=v3.33.0\n")
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
		if len(skipped) != 0 {
			t.Fatalf("skipped = %q, want empty", skipped)
		}
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
		if len(skipped) != 0 {
			t.Fatalf("skipped = %q, want empty", skipped)
		}
		return written, err
	}
}

// initGitRemote makes a bare repo to serve as root's "origin", pushes master to
// it, and returns the remote path.
func initGitRemote(t *testing.T, root string) string {
	t.Helper()
	remote := t.TempDir()
	run := func(dir string, args ...string) string {
		out, err := realGit(dir).Run(args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return out
	}
	run(remote, "init", "-q", "--bare", "-b", "master")
	run(remote, "config", "tag.gpgsign", "false")
	run(root, "remote", "add", "origin", remote)
	run(root, "push", "-q", "origin", "master")
	return remote
}

func TestValidateFreshCut(t *testing.T) {
	// Validate off skips the dirty-tree reject, so a dirty tree does not error.
	t.Run("without validate a dirty tree passes", func(t *testing.T) {
		root := initGitRepo(t)
		initGitRemote(t, root)
		_, err := realGit(root).Run("branch", "--set-upstream-to=origin/master", "master")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, root, "metadata.mk", "MANAGER_BRANCH ?= dirty\n")
		d := newTestDriver(t, Driver{RepoRoot: root, Validate: false})
		p := &CutPlan{Derived: testPrefix + "-v3.33", Source: "master"}
		if err := d.validateFreshCut(realGit(root), p); err != nil {
			t.Fatal(err)
		}
	})

	// A fresh cut with Validate rejects a dirty tree;
	// a resume and plan mode do not.
	t.Run("rejects a dirty tree", func(t *testing.T) {
		root := initGitRepo(t)
		// master is current with its upstream so the base check passes and only the
		// dirty-tree gate is under test.
		initGitRemote(t, root)
		_, err := realGit(root).Run("branch", "--set-upstream-to=origin/master", "master")
		if err != nil {
			t.Fatal(err)
		}
		// Make the tracked tree dirty.
		writeFile(t, root, "metadata.mk", "MANAGER_BRANCH ?= dirty\n")

		g := realGit(root)
		p := &CutPlan{Derived: testPrefix + "-v3.33", Source: "master"}

		d := newTestDriver(t, Driver{RepoRoot: root, Validate: true})

		// fresh cut (derived branch absent) + dirty -> rejected.
		err = d.validateFreshCut(g, p)
		if err == nil || !strings.Contains(err.Error(), "uncommitted changes") {
			t.Fatalf("error = %v, want one containing %q", err, "uncommitted changes")
		}

		// plan mode skips the dirty-tree reject.
		planD := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Plan: true})
		if err := planD.validateFreshCut(g, p); err != nil {
			t.Fatal(err)
		}

		// --skip is not a resume signal: a fresh cut with --skip still validates.
		skipD := newTestDriver(t, Driver{RepoRoot: root, Validate: true, Skip: map[string]bool{"cut-branch": true}})
		err = skipD.validateFreshCut(g, p)
		if err == nil || !strings.Contains(err.Error(), "uncommitted changes") {
			t.Fatalf("error = %v, want one containing %q", err, "uncommitted changes")
		}

		// resume: derived branch exists -> not validated even when dirty.
		_, err = realGit(root).Run("branch", p.Derived)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.validateFreshCut(g, p); err != nil {
			t.Fatal(err)
		}
	})

	// Checks the base check runs even
	// with Validate off: a main behind its upstream is still rejected.
	t.Run("checks the base without validate", func(t *testing.T) {
		root := initGitRepo(t)
		initGitRemote(t, root)
		run := func(args ...string) {
			_, err := realGit(root).Run(args...)
			if err != nil {
				t.Fatalf("git %v: %v", args, err)
			}
		}
		// Push an extra commit to origin, then reset local master back so it is behind
		// its upstream.
		run("branch", "--set-upstream-to=origin/master", "master")
		run("commit", "-q", "--allow-empty", "-m", "ahead")
		run("push", "-q", "origin", "master")
		run("reset", "-q", "--hard", "HEAD~1")

		d := newTestDriver(t, Driver{RepoRoot: root, Validate: false})
		p := &CutPlan{Derived: testPrefix + "-v3.33", Source: "master"}
		err := d.validateFreshCut(realGit(root), p)
		if err == nil || !strings.Contains(err.Error(), "not in sync") {
			t.Fatalf("error = %v, want one containing %q", err, "not in sync")
		}
	})
}
