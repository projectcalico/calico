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
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tigera/operator/hack/release/internal/setup"
	"github.com/urfave/cli/v3"
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

func validateOverrides(ctx context.Context, c *cli.Command, values []string) error {
	for _, value := range values {
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid override %q, must be in the format <image>:<version>", value)
		}
	}
	return nil
}

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

// Flag Action to check value is a valid directory.
func dirFlagCheck(_ context.Context, _ *cli.Command, path string) error {
	if path == "" {
		return nil
	}
	// Check if the directory exists
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("directory %q does not exist", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	return nil
}

// Flag Action to check value is a valid file.
func fileFlagCheck(_ context.Context, _ *cli.Command, path string) error {
	if path == "" {
		return nil
	}
	// Check if the file exists
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("file %q does not exist", path)
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory, expected a file", path)
	}
	return nil
}

// Calico related flags.
var (
	calicoFlagCategory = "Calico Options"
	calicoVersionFlag  = &cli.StringFlag{
		Name:     "calico-version",
		Category: calicoFlagCategory,
		Usage:    "The Calico version to use for the release",
		Sources:  cli.EnvVars("CALICO_VERSION"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if c.Bool(hashreleaseFlag.Name) {
				// No need to validate Calico version for hashrelease
				return nil
			}
			if valid, err := isReleaseVersionFormat(s); err != nil {
				return fmt.Errorf("error validating Calico version format: %w", err)
			} else if !valid {
				return fmt.Errorf("version %q is not a valid Calico release version", s)
			}
			return nil
		},
	}
	calicoRefFlag = &cli.StringFlag{
		Name:     "calico-ref",
		Category: calicoFlagCategory,
		Usage:    "The Calico git ref (branch or tag) to use for version config (e.g. release-vX.Y)",
		Sources:  cli.EnvVars("CALICO_REF"),
	}
	exceptCalicoFlag = &cli.StringSliceFlag{
		Name:     "except-calico",
		Category: calicoFlagCategory,
		Usage:    "Calico image and version to update where the image name adheres with config/calico_versions.yaml file. Can be specified multiple times.",
		Sources:  cli.EnvVars("OS_IMAGES_VERSIONS"),
		Action:   validateOverrides,
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
	calicoVersionsConfigFlag = &cli.StringFlag{
		Name:     "calico-versions",
		Category: calicoFlagCategory,
		Usage:    "The path to the Calico versions config file.",
		Sources:  cli.EnvVars("CALICO_VERSIONS"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("calico-versions can only be set for hashreleases")
			}
			if s != "" && c.String(calicoVersionFlag.Name) != "" {
				return fmt.Errorf("calico-versions and calico-version cannot both be set")
			}
			return fileFlagCheck(ctx, c, s)
		},
	}
	calicoDirFlag = &cli.StringFlag{
		Name:     "calico-dir",
		Category: calicoFlagCategory,
		Usage:    "The directory containing the Calico CRDs to bundle with the operator (development and testing purposes only)",
		Sources:  cli.EnvVars("CALICO_DIR"),
		Action:   dirFlagCheck,
	}
	calicoGitRepoFlag = &cli.StringFlag{
		Name:     "calico-repo",
		Category: calicoFlagCategory,
		Usage:    "The git repository to clone Calico from. Used when no Calico dir for CRDs is provided (development and testing purposes only)",
		Sources:  cli.EnvVars("CALICO_REPO"),
		Value:    "projectcalico/calico",
	}
	calicoGitBranchFlag = &cli.StringFlag{
		Name:     "calico-branch",
		Category: calicoFlagCategory,
		Usage:    "The git branch to clone Calico from. Used when no Calico dir for CRDs is provided (development and testing purposes only)",
		Sources:  cli.EnvVars("CALICO_BRANCH"),
	}
)

// Enterprise related flags.
var (
	enterpriseFlagCategory = "Enterprise Options"
	enterpriseVersionFlag  = &cli.StringFlag{
		Name:     "enterprise-version",
		Category: enterpriseFlagCategory,
		Usage:    "The Calico Enterprise version to use for the release",
		Sources:  cli.EnvVars("ENTERPRISE_VERSION"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if c.Bool(hashreleaseFlag.Name) {
				// No need to validate Enterprise version for hashrelease
				return nil
			}
			if valid, err := isEnterpriseReleaseVersionFormat(s); err != nil {
				return fmt.Errorf("error validating Enterprise version format: %w", err)
			} else if !valid {
				return fmt.Errorf("version %q is not a valid Enterprise release version", s)
			}
			return nil
		},
	}
	enterpriseRefFlag = &cli.StringFlag{
		Name:     "enterprise-ref",
		Category: enterpriseFlagCategory,
		Usage:    "The Enterprise git ref (branch or tag) to use for version config (e.g. release-calient-vX.Y-1)",
		Sources:  cli.EnvVars("ENTERPRISE_REF"),
	}
	enterpriseRegistryFlag = &cli.StringFlag{
		Name:     "enterprise-registry",
		Category: enterpriseFlagCategory,
		Usage:    "The registry Enterprise images are hosted in.",
		Sources:  cli.EnvVars("ENTERPRISE_REGISTRY"),
	}
	enterpriseImagePathFlag = &cli.StringFlag{
		Name:     "enterprise-image-path",
		Category: enterpriseFlagCategory,
		Usage:    "The path to the Enterprise images file.",
		Sources:  cli.EnvVars("ENTERPRISE_IMAGE_PATH"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("enterprise-image-path can only be set for hashreleases")
			}
			return nil
		},
	}
	enterpriseVersionsConfigFlag = &cli.StringFlag{
		Name:     "enterprise-versions",
		Category: enterpriseFlagCategory,
		Usage:    "The path to the Enterprise versions config file.",
		Sources:  cli.EnvVars("ENTERPRISE_VERSIONS"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("enterprise-versions can only be set for hashreleases")
			}
			if s != "" && c.String(enterpriseVersionFlag.Name) != "" {
				return fmt.Errorf("enterprise-versions and enterprise-version cannot both be set")
			}
			return fileFlagCheck(ctx, c, s)
		},
	}
	enterpriseDirFlag = &cli.StringFlag{
		Name:     "enterprise-dir",
		Category: enterpriseFlagCategory,
		Usage:    "The directory containing the Enterprise CRDs to bundle with the operator (development and testing purposes only)",
		Sources:  cli.EnvVars("ENTERPRISE_DIR"),
		Action:   dirFlagCheck,
	}
	enterpriseGitRepoFlag = &cli.StringFlag{
		Name:     "enterprise-repo",
		Category: enterpriseFlagCategory,
		Usage:    "The git repository to clone Enterprise from. Used when no Enterprise dir for CRDs is provided (development and testing purposes only)",
		Sources:  cli.EnvVars("ENTERPRISE_REPO"),
		Value:    "tigera/calico-private",
	}
	enterpriseGitBranchFlag = &cli.StringFlag{
		Name:     "enterprise-branch",
		Category: enterpriseFlagCategory,
		Usage:    "The git branch to clone Enterprise from. Use in place of specifying the Enterprise dir for CRDs (development and testing purposes only)",
		Sources:  cli.EnvVars("ENTERPRISE_BRANCH", "CALICO_ENTERPRISE_BRANCH"),
	}
	exceptEnterpriseFlag = &cli.StringSliceFlag{
		Name:     "except-calico-enterprise",
		Category: enterpriseFlagCategory,
		Usage:    "Enterprise image and version to update where image name adheres with config/enterprise_versions.yaml file. Can be specified multiple times.",
		Sources:  cli.EnvVars("EE_IMAGES_VERSIONS"),
		Action: func(ctx context.Context, c *cli.Command, values []string) error {
			if len(values) == 0 && len(c.StringSlice("except-calico")) == 0 {
				return fmt.Errorf("at least one of --except-calico or --except-calico-enterprise must be set")
			}
			return validateOverrides(ctx, c, values)
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
