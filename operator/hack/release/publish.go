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
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/middleware"
	"github.com/tigera/operator/hack/release/internal/setup"
	"github.com/urfave/cli/v3"
)

// Command to publish release to remote.
var publishCommand = &cli.Command{
	Name:  "publish",
	Usage: "Publish release images to remote registry and optionally create a GitHub release",
	Flags: []cli.Flag{
		versionFlag,
		imageFlag,
		archFlag,
		registryFlag,
		hashreleaseFlag,
		skipValidationFlag,
		versionCheckFlag,
		createGithubReleaseFlag,
		githubTokenFlag,
		draftGithubReleaseFlag,
	},
	Before: middleware.WithLogging(publishBefore),
	Action: middleware.WithSummary("release-publish", publishAction),
}

// Pre-action for publish command.
// It configures logging and performs validations.
var publishBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	var err error

	// Calico Cloud does not publish GitHub releases. The flag already defaults off for the cloud
	// variant (setup.CreateGitHubReleaseDefault); force it off here too so an explicit flag/env
	// request can't create one.
	if setup.IsCloud && c.Bool(createGithubReleaseFlag.Name) {
		logrus.Warn("GitHub releases are not supported for operator-cloud, disabling")
		if err := c.Set(createGithubReleaseFlag.Name, "false"); err != nil {
			return ctx, fmt.Errorf("disabling github release: %w", err)
		}
	}

	ctx, err = addRepoInfoToCtx(ctx, c.String(gitRepoFlag.Name))
	if err != nil {
		return ctx, err
	}

	// Run version validations. This is a mandatory check.
	ctx, err = checkVersion(ctx, c)
	if err != nil {
		return ctx, err
	}

	// Skip validations if requested
	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validation as requested.", c.Name)
		return ctx, nil
	}

	if c.Bool(hashreleaseFlag.Name) || !c.Bool(createGithubReleaseFlag.Name) {
		return ctx, nil
	}

	// If publishing a GitHub release, ideally it should be in draft mode with a token provided.
	if !c.Bool(draftGithubReleaseFlag.Name) {
		logrus.Warnf("Publishing GitHub release in non-draft mode.")
	}
	if c.String(githubTokenFlag.Name) == "" {
		return ctx, fmt.Errorf("GitHub token must be provided via --%s flag or GITHUB_TOKEN environment variable", githubTokenFlag.Name)
	}

	return ctx, nil
})

// Action for publish command.
var publishAction = func(ctx context.Context, c *cli.Command) (string, map[string]any, error) {
	version := c.String(versionFlag.Name)
	repoRootDir, err := command.GitDir()
	if err != nil {
		return version, nil, fmt.Errorf("getting git directory: %w", err)
	}

	// Publish images
	if err := publishImages(c, repoRootDir); err != nil {
		return version, nil, err
	}

	// Only images are published for hashrelease builds.
	if c.Bool(hashreleaseFlag.Name) {
		return version, nil, nil
	}

	// Publish GitHub release if requested
	if !c.Bool(createGithubReleaseFlag.Name) {
		logrus.Warnf("Skipping GitHub release creation. Either use %q to create a GitHub release or create manually.", publicCommand.FullName())
		return version, nil, nil
	}
	if err := publishGithubRelease(ctx, c, repoRootDir); err != nil {
		return version, nil, err
	}
	return version, nil, nil
}

// publishImages publishes the operator images to the specified registry.
// If the images are already published, it skips publishing.
var publishImages = func(c *cli.Command, repoRootDir string) error {
	version := c.String(versionFlag.Name)
	log := logrus.WithField("version", version)
	// Check if images are already published
	if published, err := operatorImagePublished(c); err != nil {
		return fmt.Errorf("checking if images are already published: %w", err)
	} else if published {
		log.Warn("Images are already published")
		return nil
	}

	// Set up environment variables for publish
	publishEnv := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", version),
	)
	if arches := c.StringSlice(archFlag.Name); len(arches) > 0 {
		log = log.WithField("arches", arches)
		publishEnv = append(publishEnv, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	}
	if image := c.String(imageFlag.Name); image != defaultImage {
		log = log.WithField("image", image)
		publishEnv = append(publishEnv, fmt.Sprintf("BUILD_IMAGE=%s", image))
	}
	if registry := c.String(registryFlag.Name); registry != "" && registry != defaultRegistry {
		log = log.WithField("registry", registry)
		publishEnv = append(publishEnv,
			fmt.Sprintf("IMAGE_REGISTRY=%s", registry),
			fmt.Sprintf("PUSH_IMAGE_PREFIXES=%s", addTrailingSlash(registry)))
	}
	if c.Bool(hashreleaseFlag.Name) {
		log = log.WithField("hashrelease", true)
		publishEnv = append(publishEnv, fmt.Sprintf("GIT_VERSION=%s", version))
	} else {
		log = log.WithField("release", true)
		publishEnv = append(publishEnv, "RELEASE=true")
	}

	log.Info("Publishing Operator images")
	if out, err := command.MakeInDir(repoRootDir, "release-publish-images", publishEnv...); err != nil {
		log.Error(out)
		return fmt.Errorf("publishing images: %w", err)
	}
	log.Info("Successfully published Operator images")
	return nil
}

// Check if the operator image is already published.
func operatorImagePublished(c *cli.Command) (bool, error) {
	registry := c.String(registryFlag.Name)
	if registry == "" {
		registry = defaultRegistry
	}
	fqImage := fmt.Sprintf("%s:%s", path.Join(registry, c.String(imageFlag.Name)), c.String(versionFlag.Name))
	ref, err := name.ParseReference(fqImage)
	if err != nil {
		return false, fmt.Errorf("failed to parse image reference for %s: %w", fqImage, err)
	}

	_, err = remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Publish a GitHub release for the operator if requested.
func publishGithubRelease(ctx context.Context, c *cli.Command, repoRootDir string) error {
	if !c.Bool(createGithubReleaseFlag.Name) {
		return nil
	}
	version := c.String(versionFlag.Name)
	isPrerelease, err := isPrereleaseVersion(repoRootDir)
	if err != nil {
		return fmt.Errorf("determining if this is a prerelease: %w", err)
	}

	r := &GithubRelease{
		Org:     ctx.Value(githubOrgCtxKey).(string),
		Repo:    ctx.Value(githubRepoCtxKey).(string),
		Version: version,
	}
	if err := r.setupClient(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return fmt.Errorf("setting up GitHub client: %s", err)
	}
	// Create the GitHub release in draft mode. If it is a prerelease, mark it as such.
	if err := r.Create(ctx, c.Bool(draftGithubReleaseFlag.Name), isPrerelease); errors.Is(err, ErrGitHubReleaseExists) {
		// Do not error out if the release already exists.
		return nil
	} else if err != nil {
		return fmt.Errorf("publishing GitHub release: %s", err)
	}
	return nil
}
