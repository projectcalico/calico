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
	"errors"
	"fmt"

	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/middleware"
	"github.com/urfave/cli/v3"
)

// Command to publish release to GitHub.
var publicCommand = &cli.Command{
	Name:    "github",
	Aliases: []string{"public"},
	Usage:   "Publish release to GitHub",
	Flags: []cli.Flag{
		versionFlag,
		draftGithubReleasePublicFlag,
		githubTokenFlag,
		skipValidationFlag,
	},
	Before: middleware.WithLogging(publicBefore),
	Action: publicAction,
}

var publicBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	var err error
	ctx, err = addRepoInfoToCtx(ctx, c.String(gitRepoFlag.Name))
	if err != nil {
		return ctx, err
	}

	if c.Bool(skipValidationFlag.Name) {
		return ctx, nil
	}

	// Check that images exist for the given version.
	if published, err := operatorImagePublished(c); err != nil {
		return ctx, fmt.Errorf("checking if images are published: %w", err)
	} else if !published {
		return ctx, fmt.Errorf("images for version %s are not published; please publish them before creating a GitHub release", c.String(versionFlag.Name))
	}

	return ctx, nil
})

var publicAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	repoRootDir, err := command.GitDir()
	if err != nil {
		return fmt.Errorf("getting repo root dir: %w", err)
	}
	isPrerelease, err := isPrereleaseVersion(repoRootDir)
	if err != nil {
		return fmt.Errorf("determining if this is a prerelease: %w", err)
	}

	r := &GithubRelease{
		Org:     ctx.Value(githubOrgCtxKey).(string),
		Repo:    ctx.Value(githubRepoCtxKey).(string),
		Version: c.String(versionFlag.Name),
	}
	if err := r.setupClient(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return fmt.Errorf("setting up GitHub client: %s", err)
	}

	if err := r.Update(ctx, c.Bool(draftGithubReleasePublicFlag.Name), isPrerelease); err != nil && errors.Is(err, ErrNoGitHubReleaseExists) {
		// If the release does not exist, create it.
		return r.Create(ctx, c.Bool(draftGithubReleasePublicFlag.Name), isPrerelease)
	} else if err != nil {
		return fmt.Errorf("updating GitHub release: %w", err)
	}
	return nil
})
