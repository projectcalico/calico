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
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/utils"
)

// Step names. --skip validates its values against stepNames.
const (
	stepCutBranch     = "cut-branch"
	stepUpdateDerived = "update-derived"
	stepUpdateSource  = "update-source"
	stepTagDerived    = "tag-derived"
	stepTagSource     = "tag-source"
	stepPushRefs      = "push-refs"
	stepPostPush      = "post-push"
)

var stepNames = []string{
	stepCutBranch,
	stepUpdateDerived,
	stepTagDerived,
	stepUpdateSource,
	stepTagSource,
	stepPushRefs,
	stepPostPush,
}

// StepNames returns the ordered step names a cut runs, for --skip validation.
func StepNames() []string {
	return slices.Clone(stepNames)
}

// Driver sequences a branch cut through its resolved plan and steps.
type Driver struct {
	// RepoRoot is the absolute path to the repository root.
	RepoRoot string

	Remote              string
	MainBranch          string
	DevTagIdentifier    string
	ReleaseBranchPrefix string

	// Validate turns on pre-branch validation (the dirty-tree reject).
	Validate bool

	// Publish pushes the branch changes to the remote.
	Publish bool

	// Plan prints what each step would do without acting.
	Plan bool

	// BranchCheck requires the source current with its remote; when false a
	// non-current source only warns. Main is always required current.
	BranchCheck bool

	Skip map[string]bool

	// PrepareDerived does the derived-branch work before its edits commit,
	// returning the changed files to stage.
	PrepareDerived func(derived string) ([]string, error)

	// PrepareSource does the source-branch work before its dev-tag commit,
	// returning the changed files to stage.
	PrepareSource func(source string) ([]string, error)

	// PostDerivedPush is the repo-specific follow-up on the derived branch after
	// the refs are pushed.
	PostDerivedPush func(derived string) error
}

// validate rejects a Driver missing a required field or carrying an unknown skip
// step.
func (d *Driver) validate() error {
	if d.RepoRoot == "" {
		return fmt.Errorf("no repository root specified")
	}
	if d.Remote == "" {
		return fmt.Errorf("no remote repository source specified")
	}
	if d.MainBranch == "" {
		return fmt.Errorf("no main branch specified")
	}
	if d.DevTagIdentifier == "" {
		return fmt.Errorf("no development tag identifier specified")
	}
	if d.ReleaseBranchPrefix == "" {
		return fmt.Errorf("no release branch prefix specified")
	}
	return validateSkip(d.Skip)
}

// validateSkip rejects any --skip value that is not a known step name.
func validateSkip(skip map[string]bool) error {
	for name := range skip {
		if !slices.Contains(stepNames, name) {
			return fmt.Errorf("unknown step %q; valid steps: %s", name, strings.Join(stepNames, ", "))
		}
	}
	return nil
}

// CutReleaseBranch cuts a release branch from the pre-built plan: the fresh-cut
// gate, then the ordered steps, resuming from the first not-done step.
func (d *Driver) CutReleaseBranch(plan *CutPlan) error {
	if err := d.validate(); err != nil {
		return err
	}
	g := gitIn(d.RepoRoot)
	if d.Plan {
		logPlan(plan)
	}
	if err := d.validateFreshCut(g, plan); err != nil {
		return err
	}
	return d.runSteps(d.steps(g, plan))
}

// logPlan prints the resolved plan under --plan: the derived branch and each
// branch that gets a dev tag.
func logPlan(p *CutPlan) {
	logrus.WithFields(logrus.Fields{
		"source":  p.Source,
		"derived": p.Derived,
		"remote":  p.Remote,
	}).Info("plan: cut derived branch from source")
	for _, t := range p.TagTargets {
		logrus.WithFields(logrus.Fields{"branch": t.Branch, "devTag": t.DevTag}).Info("plan: dev tag")
	}
}

// validateFreshCut gates a fresh cut with the dirty-tree reject (off under
// --no-validation) and the base check (always); a resume skips both.
func (d *Driver) validateFreshCut(g git, p *CutPlan) error {
	exists, err := localBranchExists(g, p.Derived)
	if err != nil {
		return err
	}
	if exists {
		logrus.WithField("branch", p.Derived).Info("derived branch already exists; skipping fresh-cut checks")
		return nil // resuming an existing cut
	}
	// --no-validation turns off only the dirty-tree reject; the base check always
	// runs. Plan mode previews both without acting.
	if d.Validate && !d.Plan {
		if dirty, err := utils.GitIsDirty(d.RepoRoot); err != nil {
			return err
		} else if dirty {
			return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before creating a new release branch")
		}
	} else if !d.Validate {
		logrus.Info("skipping the dirty-tree check (validation off)")
	}
	return d.checkBases(g, p)
}

// checkBases verifies each base is current with its remote. Main is always
// required (its upstream is .git/config); the source only under BranchCheck.
func (d *Driver) checkBases(g git, p *CutPlan) error {
	mainFix := fmt.Sprintf("run `git checkout %s && git pull` before cutting", d.MainBranch)
	if err := checkBranchCurrent(g, d.MainBranch, "", true, d.Plan, mainFix); err != nil {
		return err
	}
	if p.Source != d.MainBranch {
		srcFix := "sync it before cutting, or pass --no-branch-check to cut from the local branch as is"
		if err := checkBranchCurrent(g, p.Source, d.Remote, d.BranchCheck, d.Plan, srcFix); err != nil {
			return err
		}
	}
	return nil
}

// TagTarget is a branch that gets a dev tag. The derived branch is tagged in
// place; any other target gets a "Begin development" commit first.
type TagTarget struct {
	Branch string
	DevTag string
}

// CutPlan is the fully-resolved data description of a branch cut. The Driver
// supplies the hooks; the plan carries only data.
type CutPlan struct {
	Derived    string
	Source     string
	Remote     string
	TagTargets []TagTarget // the branches the plan builder tags (derived and/or main)
}

// CutOptions are the inputs for a branch cut.
type CutOptions interface {
	OnlyPlan() bool             // whether to act or just print what would be done
	SkipSteps() map[string]bool // the steps to skip, by name
	CheckBranch() bool          // whether to require the source branch current with its remote
}

// Step is a check-then-act unit. Done probes whether the effect is already in
// place; Do does the work.
type Step struct {
	Name string
	Done func() (bool, error)
	Do   func() error
}

// steps returns the ordered build+publish steps for the plan. g is the git
// access the steps run against.
func (d *Driver) steps(g git, p *CutPlan) []Step {
	src, hasSource := p.sourceTarget()
	// The source edit + dev-tag commit run only when the plan has a source target
	// and a source hook; the plan builder owns that decision.
	sourceGated := hasSource && d.PrepareSource != nil
	return []Step{
		{
			Name: stepCutBranch,
			Done: func() (bool, error) { return localBranchExists(g, p.Derived) },
			Do:   func() error { return createAndCheckoutBranch(g, p.Derived, p.Source) },
		},
		{
			Name: stepUpdateDerived,
			// Always re-run: the hook is idempotent and stageAndCommit skips an
			// empty commit, so a resume lands nothing new (but re-runs generate).
			Done: func() (bool, error) { return false, nil },
			Do:   func() error { return d.updateDerived(g, p) },
		},
		{
			Name: stepTagDerived,
			// Runs while HEAD is still on the derived branch, before update-source
			// switches away; a switch cannot sit between staging and tag-source.
			Done: func() (bool, error) {
				t, ok := p.derivedTarget()
				if !ok {
					return true, nil // no derived tag: the branch inherits main's tag
				}
				return localTagPointsAt(g, t.DevTag, t.Branch)
			},
			Do: func() error {
				t, ok := p.derivedTarget()
				if !ok {
					return nil
				}
				return tagHead(g, t.Branch, t.DevTag)
			},
		},
		{
			Name: stepUpdateSource,
			// Ungated: nothing to stage. Gated: re-runnable — PrepareSource is
			// idempotent and tag-source's empty commit captures what is staged.
			Done: func() (bool, error) { return !sourceGated, nil },
			Do: func() error {
				if !sourceGated {
					return nil
				}
				return d.updateSource(g, src.Branch)
			},
		},
		{
			Name: stepTagSource,
			// No source target: nothing to tag. Else done once its dev tag sits on
			// the source head; the empty commit captures the staged edit.
			Done: func() (bool, error) {
				if !hasSource {
					return true, nil
				}
				return localTagPointsAt(g, src.DevTag, src.Branch)
			},
			Do: func() error {
				if !hasSource {
					return nil
				}
				return tagWithEmptyCommit(g, src.Branch, src.DevTag)
			},
		},
		{
			Name: stepPushRefs,
			Done: func() (bool, error) {
				// A local run pushes nothing, so there is nothing to probe: report done.
				if !d.Publish {
					return true, nil
				}
				// Done only when every ref is on the remote at the local sha. A stale
				// remote ref reports not-done so it can be re-pushed.
				for _, r := range d.pushRefs(p) {
					out, err := g("rev-parse", "--verify", "--quiet", r)
					if err != nil {
						// Ref not local yet, so not on the remote: not done. This is
						// the state under --plan and before the earlier steps act.
						return false, nil
					}
					localSha := strings.TrimSpace(out)
					present, matches, err := remoteRefMatches(g, p.Remote, r, localSha)
					if err != nil {
						return false, err
					}
					if !present || !matches {
						return false, nil
					}
				}
				return true, nil
			},
			Do: func() error {
				if !d.Publish {
					logrus.Info("skipping push (local run)")
					return nil
				}
				return pushRefs(g, p.Remote, d.pushRefs(p)...)
			},
		},
		{
			Name: stepPostPush,
			// A local run pushes nothing, so post-push has no pushed branch to act
			// on: report done.
			Done: func() (bool, error) { return !d.Publish || d.PostDerivedPush == nil, nil },
			Do: func() error {
				if d.PostDerivedPush == nil {
					return nil
				}
				return d.PostDerivedPush(p.Derived)
			},
		},
	}
}

// updateDerived runs PrepareDerived on the derived branch and commits the files
// it changed.
func (d *Driver) updateDerived(g git, p *CutPlan) error {
	if err := checkoutBranch(g, p.Derived); err != nil {
		return err
	}
	var changed []string
	if d.PrepareDerived != nil {
		hookChanged, err := d.PrepareDerived(p.Derived)
		if err != nil {
			return fmt.Errorf("prepare branch: %w", err)
		}
		changed = hookChanged
	}
	committed, err := stageAndCommit(g, fmt.Sprintf("Updates for %s release branch", p.Derived), dedupe(changed))
	if err != nil {
		return err
	}
	if !committed {
		logrus.WithField("branch", p.Derived).Info("update-derived: no changes to commit")
	}
	return nil
}

// updateSource runs PrepareSource on the source branch and commits the changed
// files, so a later update-derived checkout does not carry a staged source edit.
func (d *Driver) updateSource(g git, sourceBranch string) error {
	if err := checkoutBranch(g, sourceBranch); err != nil {
		return err
	}
	changed, err := d.PrepareSource(sourceBranch)
	if err != nil {
		return fmt.Errorf("prepare source %s: %w", sourceBranch, err)
	}
	if _, err := stageAndCommit(g, fmt.Sprintf("Update %s for release branch cut", sourceBranch), dedupe(changed)); err != nil {
		return err
	}
	return nil
}

// derivedTarget returns the derived branch's tag target, if any. A cut off main
// omits it: the branch inherits main's tag through the shared commit.
func (p *CutPlan) derivedTarget() (TagTarget, bool) {
	for _, t := range p.TagTargets {
		if t.Branch == p.Derived {
			return t, true
		}
	}
	return TagTarget{}, false
}

// sourceTarget returns the non-derived (source/main) tag target, if any.
func (p *CutPlan) sourceTarget() (TagTarget, bool) {
	for _, t := range p.TagTargets {
		if t.Branch != p.Derived {
			return t, true
		}
	}
	return TagTarget{}, false
}

// pushRefs returns the refs to push, dropping any whose producing step was
// skipped (that ref was never created, so pushing it would fail).
func (d *Driver) pushRefs(p *CutPlan) []string {
	var refs []string
	if !d.Skip[stepCutBranch] {
		refs = append(refs, p.Derived)
	}
	if t, ok := p.derivedTarget(); ok && !d.Skip[stepTagDerived] {
		refs = append(refs, t.DevTag)
	}
	if src, ok := p.sourceTarget(); ok && !d.Skip[stepTagSource] {
		refs = append(refs, src.Branch, src.DevTag)
	}
	return dedupe(refs)
}

func dedupe(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// runSteps runs steps in order, skipping done or --skip steps. Plan mode acts on
// nothing. A re-run resumes from the first not-done step.
func (d *Driver) runSteps(steps []Step) error {
	for _, s := range steps {
		done, err := s.Done()
		if err != nil {
			return fmt.Errorf("%s: check: %w", s.Name, err)
		}
		switch {
		case d.Skip[s.Name]:
			logrus.WithField("step", s.Name).Info("skip (flag)")
		case done:
			logrus.WithField("step", s.Name).Info("done")
		case d.Plan:
			logrus.WithField("step", s.Name).Info("will run")
		default:
			logrus.WithField("step", s.Name).Info("running")
			if err := s.Do(); err != nil {
				return fmt.Errorf("%s: %w", s.Name, err)
			}
		}
	}
	return nil
}
