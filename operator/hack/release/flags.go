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
	"regexp"
	"slices"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/operator/hack/release/internal/setup"
)

var debugFlag = &cli.BoolFlag{
	Name:    "debug",
	Usage:   "Enable debug logging",
	Sources: cli.EnvVars("DEBUG"),
}

var extensionTimeoutFlag = &cli.DurationFlag{
	Name:    "timeout",
	Usage:   "Timeout duration for extension execution",
	Sources: cli.EnvVars("EXTENSION_TIMEOUT"),
	Value:   5 * time.Minute,
}

// Git/GitHub related flags.
var (
	githubFlagCategory = "GitHub Options"
	gitRemoteFlag      = &cli.StringFlag{
		Name:    "remote",
		Usage:   "The git remote to push the release to",
		Value:   "origin",
		Sources: cli.EnvVars("GIT_REMOTE"),
	}
	gitRepoFlag = &cli.StringFlag{
		Name:    "repo",
		Usage:   "The git repository to use",
		Value:   mainRepo,
		Sources: cli.EnvVars("REPO"),
	}
	githubTokenFlag = &cli.StringFlag{
		Name:     "github-token",
		Category: githubFlagCategory,
		Usage:    "GitHub token to use for interacting with the GitHub API",
		Sources:  cli.EnvVars("GITHUB_TOKEN"),
	}
	skipMilestoneFlag = &cli.BoolFlag{
		Name:     "skip-milestone",
		Category: developmentFlagCategory,
		Usage:    "Skip updating GitHub milestones (development and testing purposes only)",
		Sources:  cli.EnvVars("SKIP_MILESTONE"),
		Value:    false,
		Action: func(ctx context.Context, c *cli.Command, skipMilestone bool) error {
			// If not on the main repo, skip-milestone must be true if skip-git-repo-check is not set
			if c.String(gitRepoFlag.Name) != mainRepo && !skipMilestone && !c.Bool(skipRepoCheckFlag.Name) {
				return fmt.Errorf("skip-milestone is required when using a forked repo")
			}
			return nil
		},
	}
	createGithubReleaseFlag = &cli.BoolFlag{
		Name:     "create-github-release",
		Category: githubFlagCategory,
		Usage:    "Create a GitHub release",
		Sources:  cli.EnvVars("CREATE_GITHUB_RELEASE"),
		// Enterprise defaults to true; the cloud variant defaults it off (see setup package).
		Value: setup.CreateGitHubReleaseDefault,
		Action: func(ctx context.Context, c *cli.Command, b bool) error {
			if b && c.String(githubTokenFlag.Name) == "" {
				return fmt.Errorf("github-token is required to create GitHub releases")
			}
			return nil
		},
	}
	// Draft GitHub release flag for publish command. It defaults to true.
	draftGithubReleaseFlag = &cli.BoolFlag{
		Name:     "draft-github-release",
		Category: githubFlagCategory,
		Usage:    "Whether to create the GitHub release in draft mode",
		Sources:  cli.EnvVars("DRAFT_GITHUB_RELEASE"),
		Value:    true,
	}
	// Draft GitHub release flag for public command. It defaults to false.
	draftGithubReleasePublicFlag = &cli.BoolFlag{
		Name:     "draft",
		Aliases:  []string{draftGithubReleaseFlag.Name},
		Category: draftGithubReleaseFlag.Category,
		Usage:    draftGithubReleaseFlag.Usage,
		Sources:  draftGithubReleaseFlag.Sources,
		Value:    false,
	}
)

// Operator flags
var (
	operatorFlagCategory = "Operator Options"
	devTagSuffixFlag     = &cli.StringFlag{
		Name:     "dev-tag-suffix",
		Category: operatorFlagCategory,
		Usage:    "The suffix used to denote development tags",
		Sources:  cli.EnvVars("DEV_TAG_SUFFIX"),
		Value:    "0.dev",
	}
	versionFlag = &cli.StringFlag{
		Name:     "version",
		Category: operatorFlagCategory,
		Usage:    "The version of the operator to release",
		Sources:  cli.EnvVars("OPERATOR_VERSION", "VERSION"),
		Required: true,
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if c.Bool(hashreleaseFlag.Name) {
				// No need to validate version for hashrelease
				return nil
			}
			if valid, err := setup.IsValidReleaseVersion(s); err != nil {
				return fmt.Errorf("error validating version format: %w", err)
			} else if !valid {
				return fmt.Errorf("version %q is not a valid release version", s)
			}
			return nil
		},
	}
	streamFlag = &cli.StringFlag{
		Name:     "stream",
		Aliases:  []string{"release-stream"},
		Category: operatorFlagCategory,
		Usage:    "The release stream for the release branch name (e.g. vX.Y). The full branch name will be <release-branch-prefix>-<stream>",
		Sources:  cli.EnvVars("RELEASE_STREAM", "STREAM"),
		Required: true,
	}
	releaseBranchPrefixFlag = &cli.StringFlag{
		Name:     "release-branch-prefix",
		Category: operatorFlagCategory,
		Usage:    "The prefix to use for the release branch name. The full branch name will be <prefix>-<stream>",
		Sources:  cli.EnvVars("RELEASE_BRANCH_PREFIX"),
		Value:    "release",
	}
	baseOperatorFlag = &cli.StringFlag{
		Name:     "base-version",
		Category: operatorFlagCategory,
		Aliases:  []string{"base"},
		Usage:    "The version of the operator to use as the base for this new version.",
		Sources:  cli.EnvVars("OPERATOR_BASE_VERSION"),
		Required: true,
		Action: func(ctx context.Context, c *cli.Command, value string) error {
			if !regexp.MustCompile(fmt.Sprintf(baseVersionFormat, c.String(devTagSuffixFlag.Name))).MatchString(value) {
				return fmt.Errorf("base-version must be in the format vX.Y.Z or vX.Y.Z-<dev-tag-suffix>-n-g<git-hash>-<hashrelease-name> or " +
					"vX.Y.Z-<dev-tag-suffix>-n-g<git-hash>-<product-hashrelease-version>")
			}
			return nil
		},
	}
	imageFlag = &cli.StringFlag{
		Name:     "image",
		Category: operatorFlagCategory,
		Usage:    "The image name to use for the new operator (ONLY for hashreleases operator).",
		Sources:  cli.EnvVars("IMAGE_NAME"),
		Value:    defaultImage,
	}
	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:     "architecture",
		Category: operatorFlagCategory,
		Aliases:  []string{"arch"},
		Usage:    "The architecture(s) for the release. Can be specified multiple times.",
		Sources:  cli.EnvVars("ARCHS"),
		Value:    archOptions,
		Action: func(ctx context.Context, c *cli.Command, values []string) error {
			for _, arch := range values {
				if !slices.Contains(archOptions, arch) {
					return fmt.Errorf("invalid architecture %s", arch)
				}
			}
			return nil
		},
	}
	registryFlag = &cli.StringFlag{
		Name:     "registry",
		Category: operatorFlagCategory,
		Usage:    "The registry to push the new operator to (ONLY for hashreleases operator).",
		Sources:  cli.EnvVars("REGISTRY"),
		Value:    defaultRegistry,
	}
)

var publishFlag = &cli.BoolFlag{
	Name:    "publish",
	Usage:   "Publish the new operator",
	Sources: cli.EnvVars("PUBLISH"),
	Value:   false,
}

var localFlag = &cli.BoolFlag{
	Name:    "local",
	Usage:   "Run the release process locally",
	Sources: cli.EnvVars("LOCAL"),
	Value:   false,
}

// Calico related flags.
var (
	calicoFlagCategory = "Calico Options"
	calicoImageTagFlag = &cli.StringFlag{
		Name:     "calico-image-tag",
		Category: calicoFlagCategory,
		Usage:    "The tag the operator resolves Calico images at (ONLY for hashreleases). A release build uses the release version.",
		Sources:  cli.EnvVars("CALICO_IMAGE_TAG"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("calico-image-tag can only be set for hashreleases")
			}
			return nil
		},
	}
	calicoRegistryFlag = &cli.StringFlag{
		Name:     "calico-registry",
		Category: calicoFlagCategory,
		Usage:    "The registry Calico images are hosted in.",
		Sources:  cli.EnvVars("CALICO_REGISTRY"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("calico-registry can only be set for hashreleases")
			}
			return nil
		},
	}
	calicoImagePathFlag = &cli.StringFlag{
		Name:     "calico-image-path",
		Category: calicoFlagCategory,
		Usage:    "The path to the Calico images file.",
		Sources:  cli.EnvVars("CALICO_IMAGE_PATH"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("calico-image-path can only be set for hashreleases")
			}
			return nil
		},
	}
)

var (
	hashreleaseFlagEnvVar = "HASHRELEASE"
	hashreleaseFlag       = &cli.BoolFlag{
		Name:    "hashrelease",
		Usage:   "Indicates if this is a hashrelease",
		Sources: cli.EnvVars(hashreleaseFlagEnvVar),
		Value:   false,
	}
)

// General development and testing flags
var (
	developmentFlagCategory = "Development Options"
	skipValidationFlag      = &cli.BoolFlag{
		Name:     "skip-validation",
		Category: developmentFlagCategory,
		Usage:    "Skip various validation steps except version check (development and testing purposes only)",
		Sources:  cli.EnvVars("SKIP_VALIDATION"),
		Value:    false,
	}
	skipRepoCheckFlag = &cli.BoolFlag{
		Name:     "skip-repo-check",
		Category: developmentFlagCategory,
		Usage:    fmt.Sprintf("Skip checking that the git repository is %s (development and testing purposes only)", mainRepo),
		Sources:  cli.EnvVars("SKIP_REPO_CHECK"),
		Value:    false,
	}
	skipBranchCheckFlag = &cli.BoolFlag{
		Name:     "skip-branch-check",
		Category: developmentFlagCategory,
		Usage:    "Skip checking that the current git branch is master or a release branch (development and testing purposes only)",
		Sources:  cli.EnvVars("SKIP_BRANCH_CHECK"),
		Value:    false,
	}
	versionCheckFlag = &cli.BoolWithInverseFlag{
		Name:     "version-check",
		Category: developmentFlagCategory,
		Usage:    "Check that the provided version is valid and matches the git version. (development and testing purposes only)",
		Sources:  cli.EnvVars("VERSION_CHECK"),
		Value:    true,
	}
)
