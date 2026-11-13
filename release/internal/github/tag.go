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

package github

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
)

const TagStep = "github-tag"

var _ distribution.Validator = Tag{}

type TagOptions struct {
	Tag      string
	Remote   string
	RepoRoot string
	Skip     bool
	DryRun   bool
	Runner   command.CommandRunner
}

func TagUpload(o TagOptions) distribution.Upload {
	return distribution.Upload{
		Name: TagStep,
		Skip: o.Skip,
		Handler: Tag{
			Tag:    o.Tag,
			Remote: o.Remote,
			DryRun: o.DryRun,
			git:    command.Git(o.Runner).In(o.RepoRoot),
		},
	}
}

// Tag pushes a local tag to a remote.
type Tag struct {
	Tag    string
	Remote string
	DryRun bool
	git    command.GitRunner
}

func (t Tag) Name() string { return "git tag" }

func (t Tag) Validate(distribution.Upload) error {
	_, err := t.git.Resolve("refs/tags/" + t.Tag)
	if errors.Is(err, command.ErrGitRefNotFound) {
		return fmt.Errorf("no local tag %s", t.Tag)
	}
	return err
}

// Publish skips a tag the remote already has at the same commit, so a rerun
// succeeds, and fails on one at a different commit.
func (t Tag) Publish(context.Context, string) error {
	lsRemote, err := t.git.Run("ls-remote", "--tags", t.Remote, "refs/tags/"+t.Tag)
	if err != nil {
		return fmt.Errorf("query remote tag: %w", err)
	}
	if remoteSHA := remoteTagCommit(lsRemote, t.Tag); remoteSHA != "" {
		localSHA, err := t.git.Run("rev-list", "-n1", t.Tag)
		if err != nil {
			return fmt.Errorf("resolve local tag %s: %w", t.Tag, err)
		}
		localSHA = strings.TrimSpace(localSHA)
		if remoteSHA == localSHA {
			logrus.WithField("tag", t.Tag).Info("Remote tag already exists and matches, skipping push")
			return nil
		}
		return fmt.Errorf("remote tag %s already exists at %s but local tag is %s", t.Tag, remoteSHA, localSHA)
	}

	args := []string{"push", t.Remote, t.Tag}
	if t.DryRun {
		args = append(args, "--dry-run")
	}
	if _, err := t.git.Run(args...); err != nil {
		return fmt.Errorf("failed to push git tag: %w", err)
	}
	return nil
}

// remoteTagCommit returns the commit a remote tag points at. An annotated tag
// lists its peeled reference (refs/tags/<tag>^{}) with the commit SHA.
func remoteTagCommit(lsRemoteOutput, tag string) string {
	tagRef := "refs/tags/" + tag
	peeledRef := tagRef + "^{}"
	var tagObjSHA, peeledSHA string
	for _, line := range strings.Split(lsRemoteOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[1] {
		case peeledRef:
			peeledSHA = fields[0]
		case tagRef:
			tagObjSHA = fields[0]
		}
	}
	if peeledSHA != "" {
		return peeledSHA
	}
	return tagObjSHA
}
