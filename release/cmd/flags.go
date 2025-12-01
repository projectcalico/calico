// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
	"slices"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var globalFlags = append([]cli.Flag{debugFlag}, append(ciFlags, slackFlags...)...)

// debugFlag is a flag used to enable verbose log output
var debugFlag = &cli.BoolFlag{
	Name:        "debug",
	Aliases:     []string{"d"},
	Usage:       "Enable verbose log output",
	Sources:     cli.EnvVars("DEBUG"),
	Value:       false,
	Destination: &debug,
}

// Product repository flags are flags used to interact with the product repository
var (
	gitFlags     = []cli.Flag{orgFlag, repoFlag, repoRemoteFlag}
	productFlags = []cli.Flag{
		orgFlag,
		repoFlag,
		repoRemoteFlag,
		releaseBranchPrefixFlag,
		devTagSuffixFlag,
	}

	// Git flags for interacting with the git repository
	orgFlag = &cli.StringFlag{
		Name:    "org",
		Usage:   "The GitHub organization to use for the release",
		Sources: cli.EnvVars("ORGANIZATION"),
		Value:   utils.ProjectCalicoOrg,
	}
	repoFlag = &cli.StringFlag{
		Name:    "repo",
		Usage:   "The GitHub repository to use for the release",
		Sources: cli.EnvVars("GIT_REPO"),
		Value:   utils.CalicoRepoName,
	}
	repoRemoteFlag = &cli.StringFlag{
		Name:    "remote",
		Usage:   "The remote for the git repository",
		Sources: cli.EnvVars("GIT_REMOTE"),
		Value:   utils.DefaultRemote,
	}

	// Branch/Tag flags are flags used for branch & tag management
	releaseBranchPrefixFlag = &cli.StringFlag{
		Name:    "release-branch-prefix",
		Usage:   "The stardard prefix used to denote release branches",
		Sources: cli.EnvVars("RELEASE_BRANCH_PREFIX"),
		Value:   "release",
	}
	devTagSuffixFlag = &cli.StringFlag{
		Name:    "dev-tag-suffix",
		Usage:   "The suffix used to denote development tags",
		Sources: cli.EnvVars("DEV_TAG_SUFFIX"),
		Value:   "0.dev",
	}
	gitPublishFlag = &cli.BoolFlag{
		Name:    "git-publish",
		Aliases: []string{"publish-git"},
		Usage:   "Push git changes to remote. If false, all changes are local.",
		Sources: cli.EnvVars("PUBLISH_GIT"),
		Value:   true,
	}
	newBranchFlag = &cli.StringFlag{
		Name:    "branch-stream",
		Sources: cli.EnvVars("RELEASE_BRANCH_STREAM"),
		Usage:   fmt.Sprintf("The new major and minor versions for the branch to create e.g. vX.Y to create a <release-branch-prefix>-vX.Y branch e.g. v1.37 for %s-v1.37 branch", releaseBranchPrefixFlag.Value),
	}
	baseBranchFlag = &cli.StringFlag{
		Name:    "base-branch",
		Aliases: []string{"base", "main-branch"},
		Usage:   "The base branch to cut the release branch from",
		Sources: cli.EnvVars("RELEASE_BRANCH_BASE"),
		Value:   utils.DefaultBranch,
		Action: func(_ context.Context, c *cli.Command, str string) error {
			if str != utils.DefaultBranch {
				logrus.Warnf("The new branch will be created from %s which is not the default branch %s", str, utils.DefaultBranch)
			}
			return nil
		},
	}
)

// Validation flags are flags used to control validation
var (
	skipValidationFlag = &cli.BoolFlag{
		Name:    "skip-validation",
		Usage:   "Skip all validation while performing the action",
		Sources: cli.EnvVars("SKIP_VALIDATION"),
		Value:   false,
	}
)

// Container image flags are flags used to control container image building and publishing
var (
	registryFlag = &cli.StringSliceFlag{
		Name:    "registry",
		Usage:   "Override default registries for the release. Repeat for multiple registries.",
		Sources: cli.EnvVars("REGISTRIES"), // avoid DEV_REGISTRIES as it is already used by the build system (lib.Makefile).
	}

	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:    "architecture",
		Aliases: []string{"arch"},
		Usage:   "The architecture to use for the release. Repeat for multiple architectures.",
		Sources: cli.EnvVars("ARCHS"), // avoid ARCHES as it is already used by the build system (lib.Makefile).
		Value:   archOptions,
		Action: func(_ context.Context, c *cli.Command, values []string) error {
			for _, arch := range values {
				if !slices.Contains(archOptions, arch) {
					return fmt.Errorf("invalid architecture %s", arch)
				}
			}
			return nil
		},
	}

	buildImagesFlag = &cli.BoolFlag{
		Name:    "build-images",
		Usage:   "Build container images from the local code",
		Sources: cli.EnvVars("BUILD_CONTAINER_IMAGES"), // avoid BUILD_IMAGES as it is already used by the build system (lib.Makefile).
		Value:   true,
	}
	buildHashreleaseImagesFlag = &cli.BoolFlag{
		Name:    buildImagesFlag.Name,
		Usage:   buildImagesFlag.Usage,
		Sources: buildImagesFlag.Sources,
		Value:   false,
	}

	publishImagesFlag = &cli.BoolFlag{
		Name:    "publish-images",
		Usage:   "Publish images to the registry",
		Sources: cli.EnvVars("PUBLISH_IMAGES"),
		Value:   true,
	}
	publishHashreleaseImagesFlag = &cli.BoolFlag{
		Name:    publishImagesFlag.Name,
		Usage:   publishImagesFlag.Usage,
		Sources: publishImagesFlag.Sources,
		Value:   false,
	}

	archiveImagesFlag = &cli.BoolFlag{
		Name:    "archive-images",
		Usage:   "Archive images in the release tarball",
		Sources: cli.EnvVars("ARCHIVE_IMAGES"),
		Value:   true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && !c.Bool(buildImagesFlag.Name) {
				return fmt.Errorf("cannot archive images without building them; set --%s to 'true'", buildImagesFlag.Name)
			}
			return nil
		},
	}
	archiveHashreleaseImagesFlag = &cli.BoolFlag{
		Name:    archiveImagesFlag.Name,
		Usage:   archiveImagesFlag.Usage,
		Sources: archiveImagesFlag.Sources,
		Value:   false,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && !c.Bool(buildHashreleaseImagesFlag.Name) {
				return fmt.Errorf("cannot archive images without building them; set --%s to 'true'", buildHashreleaseImagesFlag.Name)
			}
			return nil
		},
	}
)

// Operator flags are flags used to interact with Tigera operator repository
var (
	operatorGitFlags   = []cli.Flag{operatorRepoRemoteFlag, operatorOrgFlag, operatorRepoFlag}
	operatorBuildFlags = []cli.Flag{
		operatorRepoRemoteFlag, operatorOrgFlag, operatorRepoFlag,
		operatorBranchFlag, operatorReleaseBranchPrefixFlag, operatorDevTagSuffixFlag,
		operatorRegistryFlag, operatorImageFlag,
	}

	// Operator git flags
	operatorOrgFlag = &cli.StringFlag{
		Name:    "operator-org",
		Usage:   "The GitHub organization to use for Tigera operator release",
		Sources: cli.EnvVars("OPERATOR_ORGANIZATION"),
		Value:   operator.DefaultOrg,
	}
	operatorRepoFlag = &cli.StringFlag{
		Name:    "operator-repo",
		Usage:   "The GitHub repository to use for Tigera operator release",
		Sources: cli.EnvVars("OPERATOR_GIT_REPO"),
		Value:   operator.DefaultRepoName,
	}
	operatorRepoRemoteFlag = &cli.StringFlag{
		Name:    "operator-git-remote",
		Usage:   "The remote for Tigera operator git repository",
		Sources: cli.EnvVars("OPERATOR_GIT_REMOTE"),
		Value:   operator.DefaultRemote,
	}

	// Branch/Tag management flags
	operatorBranchFlag = &cli.StringFlag{
		Name:    "operator-branch",
		Usage:   "The branch to use for Tigera operator release",
		Sources: cli.EnvVars("OPERATOR_BRANCH"),
		Value:   operator.DefaultBranchName,
	}
	operatorReleaseBranchPrefixFlag = &cli.StringFlag{
		Name:    "operator-release-branch-prefix",
		Usage:   "The stardard prefix used to denote Tigera operator release branches",
		Sources: cli.EnvVars("OPERATOR_RELEASE_BRANCH_PREFIX"),
		Value:   operator.DefaultReleaseBranchPrefix,
	}
	operatorDevTagSuffixFlag = &cli.StringFlag{
		Name:    "operator-dev-tag-suffix",
		Usage:   "The suffix used to denote development tags for Tigera operator",
		Sources: cli.EnvVars("OPERATOR_DEV_TAG_SUFFIX"),
		Value:   operator.DefaultDevTagSuffix,
	}
	operatorBaseBranchFlag = &cli.StringFlag{
		Name:    operatorBranchFlag.Name,
		Usage:   "The base branch to cut the Tigera operator release branch from",
		Sources: cli.EnvVars("OPERATOR_BRANCH_BASE"),
		Value:   operator.DefaultBranchName,
		Action: func(_ context.Context, c *cli.Command, str string) error {
			if str != operator.DefaultBranchName {
				logrus.Warnf("The new branch will be created from %s which is not the default branch %s", str, operator.DefaultBranchName)
			}
			return nil
		},
	}

	// Container image flags
	operatorRegistryFlag = &cli.StringFlag{
		Name:    "operator-registry",
		Usage:   "The registry to use for Tigera operator release",
		Sources: cli.EnvVars("OPERATOR_REGISTRY"),
		Value:   operator.DefaultRegistry,
	}
	operatorImageFlag = &cli.StringFlag{
		Name:    "operator-image",
		Usage:   "The image name to use for Tigera operator release",
		Sources: cli.EnvVars("OPERATOR_IMAGE"),
		Value:   operator.DefaultImage,
	}

	skipOperatorFlag = &cli.BoolFlag{
		Name:    "skip-operator",
		Usage:   "Skip building and/or publishing the operator",
		Sources: cli.EnvVars("SKIP_OPERATOR"),
		Value:   false,
	}
)

// External flags are flags used to interact with external services
var (
	// CI flags for interacting with CI services (Semaphore)
	ciFlags     = []cli.Flag{ciFlag, ciBaseURLFlag, ciJobIDFlag, ciPipelineIDFlag, ciTokenFlag}
	semaphoreCI = "semaphore"
	ciFlag      = &cli.BoolFlag{
		Name:    "ci",
		Usage:   "Run in a continuous integration (CI) environment",
		Sources: cli.EnvVars("CI"),
		Value:   false,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && (c.String(ciBaseURLFlag.Name) == "" || c.String(ciJobIDFlag.Name) == "") {
				return fmt.Errorf("CI requires %s and %s flags to be set", ciBaseURLFlag.Name, ciJobIDFlag.Name)
			}
			return nil
		},
	}
	ciBaseURLFlag = &cli.StringFlag{
		Name:    "ci-url",
		Usage:   fmt.Sprintf("The URL for accesing %s CI", semaphoreCI),
		Sources: cli.EnvVars("SEMAPHORE_ORGANIZATION_URL"),
	}
	ciJobIDFlag = &cli.StringFlag{
		Name:    "ci-job-id",
		Usage:   fmt.Sprintf("The job ID for the %s CI job", semaphoreCI),
		Sources: cli.EnvVars("SEMAPHORE_JOB_ID"),
	}
	ciPipelineIDFlag = &cli.StringFlag{
		Name:    "ci-pipeline-id",
		Usage:   fmt.Sprintf("The pipeline ID for the %s CI pipeline", semaphoreCI),
		Sources: cli.EnvVars("SEMAPHORE_PIPELINE_ID"),
	}
	ciTokenFlag = &cli.StringFlag{
		Name:    "ci-token",
		Usage:   fmt.Sprintf("The token for interacting with %s API", semaphoreCI),
		Sources: cli.EnvVars("SEMAPHORE_API_TOKEN"),
	}

	// Slack flags for posting messages to Slack
	slackFlags     = []cli.Flag{slackTokenFlag, slackChannelFlag, notifyFlag}
	slackTokenFlag = &cli.StringFlag{
		Name:    "slack-token",
		Usage:   "The Slack token to use for posting messages",
		Sources: cli.EnvVars("SLACK_API_TOKEN"),
	}
	slackChannelFlag = &cli.StringFlag{
		Name:    "slack-channel",
		Usage:   "The Slack channel to post messages",
		Sources: cli.EnvVars("SLACK_CHANNEL"),
	}
	notifyFlag = &cli.BoolFlag{
		Name:    "notify",
		Usage:   "Sending notifications to Slack",
		Sources: cli.EnvVars("NOTIFY"),
		Value:   true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			// Check slack configuration
			if b && (c.String(slackTokenFlag.Name) == "" || c.String(slackChannelFlag.Name) == "") {
				if c.Bool(ciFlag.Name) {
					return fmt.Errorf("missing Slack token or channel in CI environment")
				}
				logrus.Warnf("This command may require sending Slack notifications, ensure %s and %s flags are set", slackTokenFlag.Name, slackChannelFlag.Name)
			}
			return nil
		},
	}

	// Image scanner flags for interacting with the image scanning service
	imageScannerAPIFlags = []cli.Flag{
		imageScannerAPIFlag, imageScannerTokenFlag, imageScannerSelectFlag,
	}
	imageScannerAPIFlag = &cli.StringFlag{
		Name:    "image-scanner-api",
		Usage:   "The URL for the Image Scan Service API",
		Sources: cli.EnvVars("IMAGE_SCANNER_API"),
	}
	imageScannerTokenFlag = &cli.StringFlag{
		Name:    "image-scanner-token",
		Usage:   "The token for the Image Scan Service API",
		Sources: cli.EnvVars("IMAGE_SCANNING_TOKEN"),
	}
	imageScannerSelectFlag = &cli.StringFlag{
		Name:    "image-scanner-select",
		Usage:   "The name of the scanner to use",
		Sources: cli.EnvVars("IMAGE_SCANNER_SELECT"),
		Value:   "all",
	}
	skipImageScanFlagName = "skip-image-scan"
	skipImageScanFlag     = &cli.BoolFlag{
		Name:    skipImageScanFlagName,
		Usage:   "Skip sending the image to the image scan service",
		Sources: cli.EnvVars("SKIP_IMAGE_SCAN"),
		Value:   false,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			logrus.WithField(skipImageScanFlagName, b).Info("Image scanning configuration")
			if !b && !imageScanningAPIConfig(c).Valid() {
				if !c.Bool(ciFlag.Name) {
					logrus.Warn("Image scanning configuration is incomplete")
				}
				return fmt.Errorf("invalid configuration for image scanning. Either set --%s and --%s or set --%s to 'true'", imageScannerAPIFlag.Name, imageScannerTokenFlag.Name, skipImageScanFlagName)
			}
			return nil
		},
	}

	// GitHub API flags
	githubTokenFlag = &cli.StringFlag{
		Name:    "github-token",
		Usage:   "The GitHub token to use when interacting with the GitHub API",
		Sources: cli.EnvVars("GITHUB_TOKEN"),
		Action: func(_ context.Context, c *cli.Command, s string) error {
			if s == "" {
				if c.Bool(ciFlag.Name) {
					return fmt.Errorf("GitHub token is required")
				}
				logrus.Warn("This command requires a GitHub token")
			}
			return nil
		},
	}
)

// Release specific flags.
var (
	// Publishing flags.
	publishGitTagFlag = &cli.BoolFlag{
		Name:    "publish-git-tag",
		Usage:   "Push the git tag to the remote",
		Sources: cli.EnvVars("PUBLISH_GIT_TAG"),
		Value:   true,
	}
	publishGitHubReleaseFlag = &cli.BoolFlag{
		Name:    "publish-github-release",
		Usage:   "Publish the release to GitHub",
		Sources: cli.EnvVars("PUBLISH_GITHUB_RELEASE"),
		Value:   true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && c.String(githubTokenFlag.Name) == "" {
				return fmt.Errorf("GitHub token is required to publish release")
			}
			return nil
		},
	}
)

// Hashrelease specific flags.
var (
	skipBranchCheckFlag = &cli.BoolFlag{
		Name:    "skip-branch-check",
		Usage:   "Skip checking if current branch is a valid branch for release",
		Sources: cli.EnvVars("SKIP_BRANCH_CHECK"),
		Value:   false,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if c.Bool(skipValidationFlag.Name) && !b {
				return fmt.Errorf("must skip branch check if %s is set", skipValidationFlag)
			}
			return nil
		},
	}

	// Hashrelease server configuration flags.
	hashreleaseServerFlags = []cli.Flag{hashreleaseServerBucketFlag}
	publishHashreleaseFlag = &cli.BoolFlag{
		Name:    "publish-to-hashrelease-server",
		Usage:   "Publish the hashrelease to the hashrelease server",
		Sources: cli.EnvVars("PUBLISH_TO_HASHRELEASE_SERVER"),
		Value:   true,
	}
	latestFlag = &cli.BoolFlag{
		Name:    "latest",
		Usage:   "Publish the hashrelease as the latest hashrelease",
		Sources: cli.EnvVars("LATEST"),
		Value:   true,
	}
	hashreleaseServerBucketFlag = &cli.StringFlag{
		Name:    "hashrelease-server-bucket",
		Usage:   "The bucket name for the hashrelease server",
		Sources: cli.EnvVars("HASHRELEASE_SERVER_BUCKET"),
	}
)
