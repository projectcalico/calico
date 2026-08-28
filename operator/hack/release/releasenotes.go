// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/middleware"
	"github.com/urfave/cli/v3"
)

// Command to generate release notes.
var releaseNotesCommand = &cli.Command{
	Name:  "notes",
	Usage: "Generate release notes for a new operator release",
	Description: `Generate release notes based on merged PRs in the GitHub milestone for the specified release version.

The tag corresponding to the release version must already exist in the GitHub repository.
Otherwise, use --local flag to generate release notes based on local versions files.`,
	Aliases: []string{"release-notes"},
	Flags: []cli.Flag{
		versionFlag,
		githubTokenFlag,
		localFlag,
		skipValidationFlag,
	},
	Before: middleware.WithLogging(releaseNotesBefore),
	Action: releaseNotesAction,
}

// Pre-action for "release notes" command.
var releaseNotesBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	var err error
	ctx, err = addRepoInfoToCtx(ctx, c.String(gitRepoFlag.Name))
	if err != nil {
		return ctx, err
	}

	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validation as requested.", c.Name)
		return ctx, nil
	}

	if token := c.String(githubTokenFlag.Name); token == "" {
		return ctx, fmt.Errorf("GitHub token must be provided via --%s flag or GITHUB_TOKEN environment variable", githubTokenFlag.Name)
	}
	return ctx, nil
})

// Action executed for "release notes" command.
var releaseNotesAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	ver := c.String(versionFlag.Name)
	logrus.WithField("version", ver).Info("Generating release notes")

	release := &GithubRelease{
		Org:     ctx.Value(githubOrgCtxKey).(string),
		Repo:    ctx.Value(githubRepoCtxKey).(string),
		Version: ver,
	}
	if err := release.setupClient(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return fmt.Errorf("error setting up GitHub client: %s", err)
	}
	// get root directory of operator git repo
	repoRootDir, err := command.Run("git", []string{"rev-parse", "--show-toplevel"}, nil)
	if err != nil {
		return fmt.Errorf("error getting git root directory: %s", err)
	}
	if err := release.GenerateNotes(ctx, repoRootDir, c.Bool(localFlag.Name)); err != nil {
		return fmt.Errorf("error generating release notes: %s", err)
	}

	logrus.WithField("release-notes-file", ReleaseNotesFilePath(repoRootDir, ver)).Info("Review release notes for accuracy and format appropriately")
	logrus.Infof("Visit https://github.com/%s/%s/releases/new?tag=%s to create a new release", release.Org, release.Repo, release.Version)

	return nil
})
