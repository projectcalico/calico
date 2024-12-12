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
	"fmt"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var globalFlags = append([]cli.Flag{debugFlag}, append(ciFlags, slackFlags...)...)

// debugFlag is a flag used to enable verbose log output
var debugFlag = &cli.BoolFlag{
	Name:        "debug",
	Aliases:     []string{"d"},
	Usage:       "Enable verbose log output",
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
		EnvVars: []string{"ORGANIZATION"},
		Value:   utils.ProjectCalicoOrg,
	}
	repoFlag = &cli.StringFlag{
		Name:    "repo",
		Usage:   "The GitHub repository to use for the release",
		EnvVars: []string{"GIT_REPO"},
		Value:   utils.Calico,
	}
	repoRemoteFlag = &cli.StringFlag{
		Name:    "remote",
		Usage:   "The remote for the git repository",
		EnvVars: []string{"GIT_REMOTE"},
		Value:   utils.DefaultRemote,
	}

	// Branch/Tag flags are flags used for branch & tag management
	mainBranchFlag = &cli.StringFlag{
		Name:  "main-branch",
		Usage: "The main branch to use for the release",
		Value: utils.DefaultBranch,
	}
	releaseBranchPrefixFlag = &cli.StringFlag{
		Name:    "release-branch-prefix",
		Usage:   "The stardard prefix used to denote release branches",
		EnvVars: []string{"RELEASE_BRANCH_PREFIX"},
		Value:   "release",
	}
	devTagSuffixFlag = &cli.StringFlag{
		Name:    "dev-tag-suffix",
		Usage:   "The suffix used to denote development tags",
		EnvVars: []string{"DEV_TAG_SUFFIX"},
		Value:   "0.dev",
	}
	publishBranchFlag = &cli.BoolFlag{
		Name:  "publish-branch",
		Usage: "Push branch git. If false, all changes are local.",
		Value: true,
	}
	newBranchFlag = &cli.StringFlag{
		Name:  "branch-stream",
		Usage: fmt.Sprintf("The new major and minor versions for the branch to create e.g. vX.Y to create a %s-vX.Y branch", releaseBranchPrefixFlag.Value),
	}
	baseBranchFlag = &cli.StringFlag{
		Name:    "base-branch",
		Usage:   "The base branch to cut the release branch from",
		EnvVars: []string{"RELEASE_BRANCH_BASE"},
	}
)

// Validation flags are flags used to control validation
var (
	skipValidationFlag = &cli.BoolFlag{
		Name:    "skip-validation",
		Usage:   "Skip all validation while performing the action",
		EnvVars: []string{"SKIP_VALIDATION"},
		Value:   false,
	}
)

// Container image flags are flags used to control container image building and publishing
var (
	registryFlag = &cli.StringSliceFlag{
		Name:    "registry",
		Usage:   "Override default registries for the release. Repeat for multiple registries.",
		EnvVars: []string{"REGISTRIES"}, // avoid DEV_REGISTRIES as it is already used by the build system (lib.Makefile).
		Value:   cli.NewStringSlice(),
	}

	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:    "architecture",
		Aliases: []string{"arch"},
		Usage:   "The architecture to use for the release. Repeat for multiple architectures.",
		EnvVars: []string{"ARCHS"}, // avoid ARCHES as it is already used by the build system (lib.Makefile).
		Value:   cli.NewStringSlice(archOptions...),
		Action: func(c *cli.Context, values []string) error {
			for _, arch := range values {
				if !utils.Contains(archOptions, arch) {
					return fmt.Errorf("invalid architecture %s", arch)
				}
			}
			return nil
		},
	}

	buildImagesFlag = &cli.BoolFlag{
		Name:    "build-images",
		Usage:   "Build container images from the local code",
		EnvVars: []string{"BUILD_CONTAINER_IMAGES"}, // avoid BUILD_IMAGES as it is already used by the build system (lib.Makefile).
		Value:   true,
	}
	buildHashreleaseImageFlag = &cli.BoolFlag{
		Name:    buildImagesFlag.Name,
		Usage:   buildImagesFlag.Usage,
		EnvVars: buildImagesFlag.EnvVars,
		Value:   false,
	}

	publishImagesFlag = &cli.BoolFlag{
		Name:    "publish-images",
		Usage:   "Publish images to the registry",
		EnvVars: []string{"PUBLISH_IMAGES"},
		Value:   true,
	}
	publishHashreleaseImageFlag = &cli.BoolFlag{
		Name:    publishImagesFlag.Name,
		Usage:   publishImagesFlag.Usage,
		EnvVars: publishImagesFlag.EnvVars,
		Value:   false,
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
		EnvVars: []string{"OPERATOR_ORGANIZATION"},
		Value:   operator.DefaultOrg,
	}
	operatorRepoFlag = &cli.StringFlag{
		Name:    "operator-repo",
		Usage:   "The GitHub repository to use for Tigera operator release",
		EnvVars: []string{"OPERATOR_GIT_REPO"},
		Value:   operator.DefaultRepoName,
	}
	operatorRepoRemoteFlag = &cli.StringFlag{
		Name:    "operator-git-remote",
		Usage:   "The remote for Tigera operator git repository",
		EnvVars: []string{"OPERATOR_GIT_REMOTE"},
		Value:   operator.DefaultRemote,
	}

	// Branch/Tag management flags
	operatorBranchFlag = &cli.StringFlag{
		Name:    "operator-branch",
		Usage:   "The branch to use for Tigera operator release",
		EnvVars: []string{"OPERATOR_BRANCH"},
		Value:   operator.DefaultBranchName,
	}
	operatorReleaseBranchPrefixFlag = &cli.StringFlag{
		Name:    "operator-release-branch-prefix",
		Usage:   "The stardard prefix used to denote Tigera operator release branches",
		EnvVars: []string{"OPERATOR_RELEASE_BRANCH_PREFIX"},
		Value:   operator.DefaultReleaseBranchPrefix,
	}
	operatorDevTagSuffixFlag = &cli.StringFlag{
		Name:    "operator-dev-tag-suffix",
		Usage:   "The suffix used to denote development tags for Tigera operator",
		EnvVars: []string{"OPERATOR_DEV_TAG_SUFFIX"},
		Value:   operator.DefaultDevTagSuffix,
	}
	operatorBaseBranchFlag = &cli.StringFlag{
		Name:    operatorBranchFlag.Name,
		Usage:   "The base branch to cut the Tigera operator release branch from",
		EnvVars: []string{"OPERATOR_BRANCH_BASE"},
	}

	// Container image flags
	operatorRegistryFlag = &cli.StringFlag{
		Name:    "operator-registry",
		Usage:   "The registry to use for Tigera operator release",
		EnvVars: []string{"OPERATOR_REGISTRY"},
		Value:   operator.DefaultRegistry,
	}
	operatorImageFlag = &cli.StringFlag{
		Name:    "operator-image",
		Usage:   "The image name to use for Tigera operator release",
		EnvVars: []string{"OPERATOR_IMAGE"},
		Value:   operator.DefaultImage,
	}

	skipOperatorFlag = &cli.BoolFlag{
		Name:    "skip-operator",
		Usage:   "Skip building and/or publishing the operator",
		EnvVars: []string{"SKIP_OPERATOR"},
		Value:   false,
	}
)

// External flags are flags used to interact with external services
var (
	// CI flags for interacting with CI services (Semaphore)
	ciFlags     = []cli.Flag{ciFlag, ciBaseURLFlag, ciJobIDFlag}
	semaphoreCI = "semaphore"
	ciFlag      = &cli.BoolFlag{
		Name:    "ci",
		Usage:   "Run in a continuous integration (CI) environment",
		EnvVars: []string{"CI"},
		Value:   false,
		Action: func(ctx *cli.Context, b bool) error {
			if b && (ctx.String(ciBaseURLFlag.Name) == "" || ctx.String(ciJobIDFlag.Name) == "") {
				return fmt.Errorf("CI requires %s and %s flags to be set", ciBaseURLFlag.Name, ciJobIDFlag.Name)
			}
			return nil
		},
	}
	ciBaseURLFlag = &cli.StringFlag{
		Name:    "ci-url",
		Usage:   fmt.Sprintf("The URL for accesing %s CI", semaphoreCI),
		EnvVars: []string{"SEMAPHORE_ORGANIZATION_URL"},
	}
	ciJobIDFlag = &cli.StringFlag{
		Name:    "ci-job-id",
		Usage:   fmt.Sprintf("The job ID for the %s CI job", semaphoreCI),
		EnvVars: []string{"SEMAPHORE_JOB_ID"},
	}

	// Slack flags for posting messages to Slack
	slackFlags     = []cli.Flag{slackTokenFlag, slackChannelFlag, notifyFlag}
	slackTokenFlag = &cli.StringFlag{
		Name:    "slack-token",
		Usage:   "The Slack token to use for posting messages",
		EnvVars: []string{"SLACK_API_TOKEN"},
	}
	slackChannelFlag = &cli.StringFlag{
		Name:    "slack-channel",
		Usage:   "The Slack channel to post messages",
		EnvVars: []string{"SLACK_CHANNEL"},
	}
	notifyFlag = &cli.BoolFlag{
		Name:    "notify",
		Usage:   "Sending notifications to Slack",
		EnvVars: []string{"NOTIFY"},
		Value:   true,
		Action: func(ctx *cli.Context, b bool) error {
			// Check slack configuration
			if b && (ctx.String(slackTokenFlag.Name) == "" || ctx.String(slackChannelFlag.Name) == "") {
				if ctx.Bool(ciFlag.Name) {
					return fmt.Errorf("Slack token and channel are required in CI environment")
				}
				logrus.Warnf("This command may require sending Slack notifications, ensuure %s and %s flags are set", slackTokenFlag.Name, slackChannelFlag.Name)
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
		EnvVars: []string{"IMAGE_SCANNER_API"},
	}
	imageScannerTokenFlag = &cli.StringFlag{
		Name:    "image-scanner-token",
		Usage:   "The token for the Image Scan Service API",
		EnvVars: []string{"IMAGE_SCANNING_TOKEN"},
	}
	imageScannerSelectFlag = &cli.StringFlag{
		Name:    "image-scanner-select",
		Usage:   "The name of the scanner to use",
		EnvVars: []string{"IMAGE_SCANNER_SELECT"},
		Value:   "all",
	}
	skipImageScanFlag = &cli.BoolFlag{
		Name:    "skip-image-scan",
		Usage:   "Skip sending the image to the image scan service",
		EnvVars: []string{"SKIP_IMAGE_SCAN"},
		Value:   false,
		Action: func(ctx *cli.Context, b bool) error {
			if !b && (ctx.String(imageScannerAPIFlag.Name) == "" || ctx.String(imageScannerTokenFlag.Name) == "") {
				return fmt.Errorf("Image scanner configuration is required, ensure %s and %s flags are set", imageScannerAPIFlag.Name, imageScannerTokenFlag.Name)
			}
			return nil
		},
	}

	// GitHub API flags
	githubTokenFlag = &cli.StringFlag{
		Name:    "github-token",
		Usage:   "The GitHub token to use when interacting with the GitHub API",
		EnvVars: []string{"GITHUB_TOKEN"},
		Action: func(ctx *cli.Context, s string) error {
			if s == "" {
				if ctx.Bool(ciFlag.Name) {
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
		Name:  "publish-git-tag",
		Usage: "Push the git tag to the remote",
		Value: true,
	}
	publishGitHubReleaseFlag = &cli.BoolFlag{
		Name:  "publish-github-release",
		Usage: "Publish the release to GitHub",
		Value: true,
	}
)

// Hashrelease specific flags.
var (
	skipBranchCheckFlag = &cli.BoolFlag{
		Name:    "skip-branch-check",
		Usage:   "Skip checking if current branch is a valid branch for release",
		EnvVars: []string{"SKIP_BRANCH_CHECK"},
		Value:   false,
		Action: func(c *cli.Context, b bool) error {
			if c.Bool(skipValidationFlag.Name) && !b {
				return fmt.Errorf("must skip branch check if %s is set", skipValidationFlag)
			}
			return nil
		},
	}

	// Hashrelease server configuration flags.
	hashreleaseServerFlags = []cli.Flag{
		sshHostFlag, sshUserFlag, sshKeyFlag, sshPortFlag,
		sshKnownHostsFlag,
	}
	sshHostFlag = &cli.StringFlag{
		Name:    "server-ssh-host",
		Usage:   "The SSH host for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_HOST"},
	}
	sshUserFlag = &cli.StringFlag{
		Name:    "server-ssh-user",
		Usage:   "The SSH user for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_USER"},
	}
	sshKeyFlag = &cli.StringFlag{
		Name:    "server-ssh-key",
		Usage:   "The SSH key for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_KEY"},
	}
	sshPortFlag = &cli.StringFlag{
		Name:    "server-ssh-port",
		Usage:   "The SSH port for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_PORT"},
	}
	sshKnownHostsFlag = &cli.StringFlag{
		Name: "sever-ssh-known-hosts",
		Usage: "The known_hosts file is the absolute path to the known_hosts file " +
			"to use for the user host key database instead of ~/.ssh/known_hosts",
		EnvVars: []string{"DOCS_KNOWN_HOSTS"},
	}
	maxHashreleasesFlag = &cli.IntFlag{
		Name:    "maxiumum",
		Aliases: []string{"max"},
		Usage:   "The maximum number of hashreleases to keep on the hashrelease server",
		Value:   hashreleaseserver.DefaultMax,
	}
	publishHashreleaseFlag = &cli.BoolFlag{
		Name:  "publish-to-hashrelease-server",
		Usage: "Publish the hashrelease to the hashrelease server",
		Value: true,
	}
	latestFlag = &cli.BoolFlag{
		Name:  "latest",
		Usage: "Publish the hashrelease as the latest hashrelease",
		Value: true,
	}
)
