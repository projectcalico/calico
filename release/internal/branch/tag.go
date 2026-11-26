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
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
)

// tagRefPrefix marks a cut source that is a tag rather than a branch.
const tagRefPrefix = "refs/tags/"

const (
	CreateTagStep = "create-tag"
	PushTagStep   = "push-tag"
)

// TagSource returns the cut source for cutting from tagName.
func TagSource(tagName string) string {
	return tagRefPrefix + tagName
}

// checkTagOnRemote verifies tagName exists locally and on remote at the same
// commit. Under report (plan mode) a mismatch is a warning; a failed remote
// query is always an error.
func checkTagOnRemote(g command.GitRunner, tagName, remote string, report bool) error {
	out, err := lsRemoteTag(g, tagName, remote)
	if err != nil {
		return err
	}
	problem := tagMismatch(g, tagName, remote, out)
	if problem == nil {
		return nil
	}
	if report {
		logrus.Warnf("%v; a cut will error unless resolved", problem)
		return nil
	}
	return problem
}

// lsRemoteTag lists tagName on remote, or nothing when the remote lacks it.
func lsRemoteTag(g command.GitRunner, tagName, remote string) (string, error) {
	ref := tagRefPrefix + tagName
	// ls-remote lists an annotated tag's peeled commit under "<ref>^{}".
	out, err := g.Run("ls-remote", remote, ref, ref+"^{}")
	if err != nil {
		return "", fmt.Errorf("checking %s on %s: %w", ref, remote, err)
	}
	return out, nil
}

// tagMismatch compares the local tag with the remote's, given its ls-remote output.
func tagMismatch(g command.GitRunner, tagName, remote, lsRemote string) error {
	ref := tagRefPrefix + tagName
	want, err := g.Resolve(ref + "^{commit}")
	if errors.Is(err, command.ErrGitRefNotFound) {
		return fmt.Errorf("tag mismatch: %s does not exist locally; fetch it with `git fetch %s tag %s`", tagName, remote, tagName)
	}
	if err != nil {
		return fmt.Errorf("tag mismatch: %w", err)
	}
	commits := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(lsRemote), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			commits[f[1]] = f[0]
		}
	}
	got := cmp.Or(commits[ref+"^{}"], commits[ref])
	if got == "" {
		return fmt.Errorf("tag mismatch: %s is not on %s; only a released tag can be cut from", tagName, remote)
	}
	if got != want {
		return fmt.Errorf("tag mismatch: local tag %s (%s) does not match %s (%s)", tagName, want, remote, got)
	}
	return nil
}

// TagAtHEAD reports whether tagName is on HEAD. A missing tag reports false;
// one on another commit is an error.
func TagAtHEAD(g command.GitRunner, tagName string) (bool, error) {
	return tagAt(g, tagName, "HEAD")
}

func tagAt(g command.GitRunner, tagName, rev string) (bool, error) {
	tagCommit, err := g.Resolve(tagRefPrefix + tagName + "^{commit}")
	if errors.Is(err, command.ErrGitRefNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want, err := g.Resolve(rev + "^{commit}")
	if err != nil {
		return false, err
	}
	if tagCommit != want {
		return false, fmt.Errorf("tag %s already exists at %s but %s is %s", tagName, tagCommit, rev, want)
	}
	return true, nil
}

type tagSpec struct {
	message string
	move    bool
	commit  string
}

type TagOption func(*tagSpec)

// TagMessage makes an annotated tag.
func TagMessage(msg string) TagOption {
	return func(s *tagSpec) { s.message = msg }
}

// TagCommit tags commit instead of HEAD.
func TagCommit(commit string) TagOption {
	return func(s *tagSpec) { s.commit = commit }
}

// MoveTag lets a tag on another commit move to the target.
// Only a tag that was never pushed is safe to move.
func MoveTag() TagOption {
	return func(s *tagSpec) { s.move = true }
}

// CreateTag tags HEAD, lightweight unless given a message. A tag already on
// its commit is kept, so a rerun succeeds; one elsewhere is an error unless moved.
func CreateTag(g command.GitRunner, tagName string, opts ...TagOption) error {
	var s tagSpec
	for _, opt := range opts {
		opt(&s)
	}
	target := cmp.Or(s.commit, "HEAD")
	if !s.move {
		exists, err := tagAt(g, tagName, target)
		if err != nil {
			return err
		}
		if exists {
			logrus.WithFields(logrus.Fields{"tag": tagName, "commit": target}).Info("Tag already exists, skipping tag creation")
			return nil
		}
	}
	args := []string{"tag"}
	if s.move {
		args = append(args, "-f")
	}
	if s.message != "" {
		args = append(args, "-a", "-m", s.message)
	} else {
		args = append(args, "--no-sign")
	}
	args = append(args, tagName)
	if s.commit != "" {
		args = append(args, s.commit)
	}
	if _, err := g.Run(args...); err != nil {
		return fmt.Errorf("tag %s: %w", tagName, err)
	}
	return nil
}

func DeleteTag(g command.GitRunner, tagName string) error {
	if _, err := g.Run("tag", "-d", tagName); err != nil {
		return fmt.Errorf("delete tag %s: %w", tagName, err)
	}
	return nil
}

type PushTagOptions struct {
	Tag      string
	Remote   string
	RepoRoot string
	Skip     bool
	DryRun   bool
	Runner   command.CommandRunner
}

func TagUpload(o PushTagOptions) distribution.Upload {
	return distribution.Upload{
		Name: PushTagStep,
		Skip: o.Skip,
		Handler: TagPush{
			Tag:    o.Tag,
			Remote: o.Remote,
			DryRun: o.DryRun,
			git:    command.Git(o.Runner).In(o.RepoRoot),
		},
	}
}

var _ distribution.Validator = TagPush{}

// TagPush pushes a local tag to a remote.
type TagPush struct {
	Tag    string
	Remote string
	DryRun bool
	git    command.GitRunner
}

func (t TagPush) Name() string { return "git tag" }

func (t TagPush) Validate(distribution.Upload) error {
	var errs []error
	if t.Remote == "" {
		errs = append(errs, fmt.Errorf("no git remote for tag %s", t.Tag))
	}
	_, err := t.git.Resolve(tagRefPrefix + t.Tag)
	if errors.Is(err, command.ErrGitRefNotFound) {
		err = fmt.Errorf("no local tag %s", t.Tag)
	}
	return errors.Join(append(errs, err)...)
}

// Publish skips a tag the remote already has at the same commit, so a rerun
// succeeds, and fails on one at a different commit.
func (t TagPush) Publish(context.Context, string) error {
	out, err := lsRemoteTag(t.git, t.Tag, t.Remote)
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		if err := tagMismatch(t.git, t.Tag, t.Remote, out); err != nil {
			return err
		}
		logrus.WithField("tag", t.Tag).Info("Remote tag already exists and matches, skipping push")
		return nil
	}
	if err := pushRefs(t.git, t.Remote, t.DryRun, tagRefPrefix+t.Tag); err != nil {
		return fmt.Errorf("push tag %s: %w", t.Tag, err)
	}
	return nil
}
