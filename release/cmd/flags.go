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
	gitCategory = "Git Repository"
	orgFlag     = &cli.StringFlag{
		Name:     "org",
		Category: gitCategory,
		Usage:    "The GitHub organization to use for the release",
		Sources:  cli.EnvVars("ORGANIZATION"),
		Value:    utils.ProjectCalicoOrg,
	}
	repoFlag = &cli.StringFlag{
		Name:     "repo",
		Category: gitCategory,
		Usage:    "The GitHub repository to use for the release",
		Sources:  cli.EnvVars("GIT_REPO"),
		Value:    utils.CalicoRepoName,
	}
	repoRemoteFlag = &cli.StringFlag{
		Name:     "remote",
		Category: gitCategory,
		Usage:    "The remote for the git repository",
		Sources:  cli.EnvVars("GIT_REMOTE"),
		Value:    utils.DefaultRemote,
	}

	// Branch/Tag flags are flags used for branch & tag management
	releaseBranchPrefixFlag = &cli.StringFlag{
		Name:     "release-branch-prefix",
		Category: gitCategory,
		Usage:    "The stardard prefix used to denote release branches",
		Sources:  cli.EnvVars("RELEASE_BRANCH_PREFIX"),
		Value:    "release",
	}
	devTagSuffixFlag = &cli.StringFlag{
		Name:     "dev-tag-suffix",
		Category: gitCategory,
		Usage:    "The suffix used to denote development tags",
		Sources:  cli.EnvVars("DEV_TAG_SUFFIX"),
		Value:    "0.dev",
	}
	baseBranchFlag = &cli.StringFlag{
		Name:     "base-branch",
		Category: gitCategory,
		Aliases:  []string{"base", "main-branch"},
		Usage:    "The base branch to cut the release branch from",
		Sources:  cli.EnvVars("RELEASE_BRANCH_BASE"),
		Value:    utils.DefaultBranch,
		Action: func(_ context.Context, c *cli.Command, str string) error {
			if str != utils.DefaultBranch {
				logrus.Warnf("The new branch will be created from %s which is not the default branch %s", str, utils.DefaultBranch)
			}
			return nil
		},
	}
)

// Mode flags control the execution mode of the release tool.
var (
	localFlag = &cli.BoolFlag{
		Name:    "local",
		Usage:   "Run all actions locally without remote changes",
		Sources: cli.EnvVars("LOCAL"),
		Value:   false,
	}
)

// Development flags are flags used to control development behavior of the release process
var (
	developmentCategory = "Development"

	skipValidationFlag = &cli.BoolFlag{
		Name:     "skip-validation",
		Category: developmentCategory,
		Usage:    "Skip all validation while performing the action",
		Sources:  cli.EnvVars("SKIP_VALIDATION"),
		Value:    false,
	}
	skipBranchCheckFlag = &cli.BoolFlag{
		Name:     "skip-branch-check",
		Category: developmentCategory,
		Usage:    "Skip checking if current branch is a valid branch for release",
		Sources:  cli.EnvVars("SKIP_BRANCH_CHECK"),
		Value:    false,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if c.Bool(skipValidationFlag.Name) && !b {
				return fmt.Errorf("must skip branch check if %s is set", skipValidationFlag)
			}
			return nil
		},
	}
)

// Container image flags are flags used to control container image building and publishing
var (
	containerImageCategory = "Container Image"
	registryFlag           = &cli.StringSliceFlag{
		Name:     "registry",
		Category: containerImageCategory,
		Usage:    "Override default registries for the release. Repeat for multiple registries.",
		Sources:  cli.EnvVars("REGISTRIES"), // avoid DEV_REGISTRIES as it is already used by the build system (lib.Makefile).
	}
	helmRegistryFlag = &cli.StringSliceFlag{
		Name:     "helm-registry",
		Category: containerImageCategory,
		Usage:    "Override default OCI-based helm chart registries for the release. Repeat for multiple registries.",
		Sources:  cli.EnvVars("HELM_REGISTRIES"),
	}

	archOptions = []string{"amd64", "arm64", "ppc64le", "s390x"}
	archFlag    = &cli.StringSliceFlag{
		Name:     "architecture",
		Category: containerImageCategory,
		Aliases:  []string{"arch"},
		Usage:    "The architecture to use for the release. Repeat for multiple architectures.",
		Sources:  cli.EnvVars("ARCHS"), // avoid ARCHES as it is already used by the build system (lib.Makefile).
		Value:    archOptions,
		Action: func(_ context.Context, c *cli.Command, values []string) error {
			for _, arch := range values {
				if !slices.Contains(archOptions, arch) {
					return fmt.Errorf("invalid architecture %s", arch)
				}
			}
			return nil
		},
	}
)

var (
	cloudCategory  = "Cloud Configuration"
	awsProfileFlag = &cli.StringFlag{
		Name:     "aws-profile",
		Category: cloudCategory,
		Usage:    "The AWS profile to use",
		Sources:  cli.EnvVars("AWS_PROFILE"),
	}
	s3BucketFlag = &cli.StringFlag{
		Name:     "s3-bucket",
		Category: cloudCategory,
		Usage:    "The S3 bucket to publish release artifacts to.",
		Sources:  cli.EnvVars("S3_BUCKET"),
	}
)

// Operator flags are flags used to interact with Tigera operator repository
var (
	operatorCategory   = "Tigera Operator"
	operatorGitFlags   = []cli.Flag{operatorOrgFlag, operatorRepoFlag}
	operatorBuildFlags = append(operatorGitFlags, operatorFlag,
		operatorBranchFlag, operatorReleaseBranchPrefixFlag,
		operatorRegistryFlag, operatorImageFlag)

	// Operator git flags
	operatorOrgFlag = &cli.StringFlag{
		Name:     "operator-org",
		Category: operatorCategory,
		Usage:    "The GitHub organization to use for Tigera operator release",
		Sources:  cli.EnvVars("OPERATOR_ORGANIZATION"),
		Value:    operator.DefaultOrg,
	}
	operatorRepoFlag = &cli.StringFlag{
		Name:     "operator-repo",
		Category: operatorCategory,
		Usage:    "The GitHub repository to use for Tigera operator release",
		Sources:  cli.EnvVars("OPERATOR_GIT_REPO"),
		Value:    operator.DefaultRepoName,
	}
	// Branch/Tag management flags
	operatorBranchFlag = &cli.StringFlag{
		Name:     "operator-branch",
		Category: operatorCategory,
		Usage:    "The branch to use for Tigera operator release",
		Sources:  cli.EnvVars("OPERATOR_BRANCH"),
		Value:    operator.DefaultBranchName,
	}
	operatorReleaseBranchPrefixFlag = &cli.StringFlag{
		Name:     "operator-release-branch-prefix",
		Category: operatorCategory,
		Usage:    "The stardard prefix used to denote Tigera operator release branches",
		Sources:  cli.EnvVars("OPERATOR_RELEASE_BRANCH_PREFIX"),
		Value:    operator.DefaultReleaseBranchPrefix,
	}
	// Container image flags
	operatorRegistryFlag = &cli.StringFlag{
		Name:     "operator-registry",
		Category: operatorCategory,
		Usage:    "The registry to use for Tigera operator release",
		Sources:  cli.EnvVars("OPERATOR_REGISTRY"),
		Value:    operator.DefaultRegistry,
	}
	operatorImageFlag = &cli.StringFlag{
		Name:     "operator-image",
		Category: operatorCategory,
		Usage:    "The image name to use for Tigera operator release",
		Sources:  cli.EnvVars("OPERATOR_IMAGE"),
		Value:    operator.DefaultImage,
	}

	operatorFlag = &cli.BoolFlag{
		Name:     "operator",
		Category: operatorCategory,
		Usage:    "Include Tigera operator in the release steps",
		Sources:  cli.EnvVars("OPERATOR"),
		Value:    true,
	}
)

// External flags are flags used to interact with external services
var (
	// CI flags for interacting with CI services (Semaphore)
	ciCategory  = "CI Environment"
	ciFlags     = []cli.Flag{ciFlag, ciBaseURLFlag, ciJobIDFlag, ciPipelineIDFlag, ciTokenFlag}
	semaphoreCI = "semaphore"
	ciFlag      = &cli.BoolFlag{
		Name:     "ci",
		Category: ciCategory,
		Usage:    "Run in a continuous integration (CI) environment",
		Sources:  cli.EnvVars("CI"),
		Value:    false,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && (c.String(ciBaseURLFlag.Name) == "" || c.String(ciJobIDFlag.Name) == "") {
				return fmt.Errorf("CI requires %s and %s flags to be set", ciBaseURLFlag.Name, ciJobIDFlag.Name)
			}
			return nil
		},
	}
	ciBaseURLFlag = &cli.StringFlag{
		Name:     "ci-url",
		Category: ciCategory,
		Usage:    fmt.Sprintf("The URL for accesing %s CI", semaphoreCI),
		Sources:  cli.EnvVars("SEMAPHORE_ORGANIZATION_URL"),
	}
	ciJobIDFlag = &cli.StringFlag{
		Name:     "ci-job-id",
		Category: ciCategory,
		Usage:    fmt.Sprintf("The job ID for the %s CI job", semaphoreCI),
		Sources:  cli.EnvVars("SEMAPHORE_JOB_ID"),
	}
	ciPipelineIDFlag = &cli.StringFlag{
		Name:     "ci-pipeline-id",
		Category: ciCategory,
		Usage:    fmt.Sprintf("The pipeline ID for the %s CI pipeline", semaphoreCI),
		Sources:  cli.EnvVars("SEMAPHORE_PIPELINE_ID"),
	}
	ciTokenFlag = &cli.StringFlag{
		Name:     "ci-token",
		Category: ciCategory,
		Usage:    fmt.Sprintf("The token for interacting with %s API", semaphoreCI),
		Sources:  cli.EnvVars("SEMAPHORE_API_TOKEN"),
	}

	// Slack flags for posting messages to Slack
	slackCategory  = "Slack"
	slackFlags     = []cli.Flag{slackTokenFlag, slackChannelFlag, notifyFlag}
	slackTokenFlag = &cli.StringFlag{
		Name:     "slack-token",
		Category: slackCategory,
		Usage:    "The Slack token to use for posting messages",
		Sources:  cli.EnvVars("SLACK_API_TOKEN"),
	}
	slackChannelFlag = &cli.StringFlag{
		Name:     "slack-channel",
		Category: slackCategory,
		Usage:    "The Slack channel to post messages",
		Sources:  cli.EnvVars("SLACK_CHANNEL"),
	}
	notifyFlag = &cli.BoolFlag{
		Name:     "notify",
		Category: slackCategory,
		Usage:    "Sending notifications to Slack",
		Sources:  cli.EnvVars("NOTIFY"),
		Value:    true,
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
	imageScannerCategory = "Image Scanning Service"
	imageScanFlags       = []cli.Flag{
		skipImageScanFlag,
		imageScannerAPIFlag,
		imageScannerTokenFlag,
		imageScannerSelectFlag,
	}
	imageScannerAPIFlag = &cli.StringFlag{
		Name:     "image-scanner-api",
		Category: imageScannerCategory,
		Usage:    "The URL for the Image Scanning Service API",
		Sources:  cli.EnvVars("IMAGE_SCANNER_API"),
	}
	imageScannerTokenFlag = &cli.StringFlag{
		Name:     "image-scanner-token",
		Category: imageScannerCategory,
		Usage:    "The token for the Image Scanning Service API",
		Sources:  cli.EnvVars("IMAGE_SCANNING_TOKEN"),
	}
	imageScannerSelectFlag = &cli.StringFlag{
		Name:     "image-scanner-select",
		Category: imageScannerCategory,
		Usage:    "The name of the scanner to use",
		Sources:  cli.EnvVars("IMAGE_SCANNER_SELECT"),
		Value:    "all",
	}
	skipImageScanFlagName = "skip-image-scan"
	skipImageScanFlag     = &cli.BoolFlag{
		Name:     skipImageScanFlagName,
		Category: imageScannerCategory,
		Usage:    "Skip sending the image to the image scan service",
		Sources:  cli.EnvVars("SKIP_IMAGE_SCAN"),
		Value:    false,
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

// Hashrelease specific flags.
var (

	// Hashrelease server configuration flags.
	hashreleaseServerCategory = "Hashrelease Server"
	hashreleaseServerFlags    = []cli.Flag{hashreleaseServerBucketFlag}
	publishHashreleaseFlag    = &cli.BoolFlag{
		Name:     "publish-to-hashrelease-server",
		Category: hashreleaseServerCategory,
		Usage:    "Publish the hashrelease to the hashrelease server",
		Sources:  cli.EnvVars("PUBLISH_TO_HASHRELEASE_SERVER"),
		Value:    true,
	}
	latestFlag = &cli.BoolFlag{
		Name:     "latest",
		Category: hashreleaseServerCategory,
		Usage:    "Publish the hashrelease as the latest hashrelease",
		Sources:  cli.EnvVars("LATEST"),
		Value:    true,
	}
	hashreleaseServerBucketFlag = &cli.StringFlag{
		Name:     "hashrelease-server-bucket",
		Category: hashreleaseServerCategory,
		Usage:    "The bucket name for the hashrelease server",
		Sources:  cli.EnvVars("HASHRELEASE_SERVER_BUCKET"),
	}
)

// Step control flags gate logical release steps.
const (
	stepControlCategory = "Step Control"

	// Images.
	imagesFlagName        = "images"
	envBuildImages        = "BUILD_CONTAINER_IMAGES"
	envPublishImages      = "PUBLISH_IMAGES"
	archiveImagesFlagName = "archive-images"
	envArchiveImages      = "ARCHIVE_IMAGES"

	// Helm Charts.
	helmChartsFlagName = "helm-charts"
	envBuildCharts     = "BUILD_CHARTS"
	envPublishCharts   = "PUBLISH_CHARTS"

	// Windows.
	windowsArchiveFlagName   = "windows-archive"
	envBuildWindowsArchive   = "BUILD_WINDOWS_ARCHIVE"
	envPublishWindowsArchive = "PUBLISH_WINDOWS_ARCHIVE"
)

var (
	buildStepFlags = func(hashrelease bool) []cli.Flag {
		return []cli.Flag{
			manifestsFlag,
			ocpBundleFlag,
			imagesFlag(!hashrelease, envBuildImages),
			archiveImagesFlag(!hashrelease, envArchiveImages),
			binariesFlag,
			helmChartsFlag(true, envBuildCharts),
			helmIndexFlag,
			tarballFlag,
			windowsArchiveFlag(true, envBuildWindowsArchive),
		}
	}
	publishStepFlags = func(hashrelease bool) []cli.Flag {
		f := buildStepFlags(hashrelease)
		if hashrelease {
			return f
		}
		return append(f,
			gitRefFlag,
			githubReleaseFlag)
	}

	imagesFlag = func(value bool, envVars ...string) *cli.BoolFlag {
		return &cli.BoolFlag{
			Name:     imagesFlagName,
			Category: stepControlCategory,
			Usage:    "Include container images in the release step",
			Sources:  cli.EnvVars(envVars...),
			Value:    value,
		}
	}
	archiveImagesFlag = func(value bool, envVars ...string) *cli.BoolFlag {
		return &cli.BoolFlag{
			Name:     archiveImagesFlagName,
			Category: stepControlCategory,
			Usage:    "Archive container images in the release tarball",
			Sources:  cli.EnvVars(envVars...),
			Value:    value,
			Action: func(_ context.Context, c *cli.Command, b bool) error {
				if b && !c.Bool(imagesFlagName) {
					return fmt.Errorf("cannot archive images without building them; set --%s to 'true'", imagesFlagName)
				}
				return nil
			},
		}
	}
	helmChartsFlag = func(value bool, envVars ...string) *cli.BoolFlag {
		return &cli.BoolFlag{
			Name:     helmChartsFlagName,
			Category: stepControlCategory,
			Usage:    "Include Helm charts in the release step",
			Sources:  cli.EnvVars(envVars...),
			Value:    value,
		}
	}
	helmIndexFlag = &cli.BoolFlag{
		Name:     "helm-index",
		Category: stepControlCategory,
		Usage:    "Update the Helm chart index",
		Sources:  cli.EnvVars("RELEASE_HELM_INDEX", "UPDATE_HELM_INDEX"),
		Value:    true,
	}
	binariesFlag = &cli.BoolFlag{
		Name:     "binaries",
		Category: stepControlCategory,
		Usage:    "Include binaries in the release step",
		Sources:  cli.EnvVars("RELEASE_BINARIES"),
		Value:    true,
	}
	manifestsFlag = &cli.BoolFlag{
		Name:     "manifests",
		Category: stepControlCategory,
		Usage:    "Include manifests in the release step",
		Sources:  cli.EnvVars("RELEASE_MANIFESTS"),
		Value:    true,
	}
	ocpBundleFlag = &cli.BoolFlag{
		Name:     "ocp-bundle",
		Category: stepControlCategory,
		Usage:    "Include OCP bundle in the release step",
		Sources:  cli.EnvVars("RELEASE_OCP_BUNDLE"),
		Value:    true,
	}
	windowsArchiveFlag = func(value bool, envVars ...string) *cli.BoolFlag {
		return &cli.BoolFlag{
			Name:     windowsArchiveFlagName,
			Category: stepControlCategory,
			Usage:    "Include Windows archive in the release step",
			Sources:  cli.EnvVars(envVars...),
			Value:    value,
		}
	}
	tarballFlag = &cli.BoolFlag{
		Name:     "tarball",
		Category: stepControlCategory,
		Usage:    "Include the release tarball in the release step",
		Sources:  cli.EnvVars("RELEASE_TARBALL"),
		Value:    true,
	}
	gitRefFlag = &cli.BoolFlag{
		Name:     "git-ref",
		Category: stepControlCategory,
		Usage:    "Push the git ref(s) to the remote",
		Sources:  cli.EnvVars("PUBLISH_GIT_TAG", "PUBLISH_GIT_REF"),
		Value:    true,
	}
	githubReleaseFlag = &cli.BoolFlag{
		Name:     "github-release",
		Category: stepControlCategory,
		Usage:    "Publish the GitHub release",
		Sources:  cli.EnvVars("PUBLISH_GITHUB_RELEASE"),
		Value:    true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && c.String(githubTokenFlag.Name) == "" {
				return fmt.Errorf("GitHub token is required to publish release")
			}
			return nil
		},
	}
)
