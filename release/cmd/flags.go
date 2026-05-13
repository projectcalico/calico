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

	"github.com/projectcalico/calico/release/internal/defaults"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var globalFlags = append([]cli.Flag{debugFlag}, append(ciFlags, slackFlags...)...)

// Flag categories group flags in --help output.
const (
	gitCategory               = "Git Repository"
	developmentCategory       = "Development"
	containerImageCategory    = "Container Image"
	cloudCategory             = "Cloud Configuration"
	operatorCategory          = "Tigera Operator"
	ciCategory                = "CI Environment"
	slackCategory             = "Slack"
	imageScannerCategory      = "Image Scanning Service"
	hashreleaseServerCategory = "Hashrelease Server"
	stepControlCategory       = "Step Control"
)

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
	productFlags = []cli.Flag{
		orgFlag,
		repoFlag,
		repoRemoteFlag,
		releaseBranchPrefixFlag,
		devTagSuffixFlag,
	}

	// Git flags for interacting with the git repository
	orgFlagName = "org"
	orgFlag     = &cli.StringFlag{
		Name:     orgFlagName,
		Category: gitCategory,
		Usage:    "The GitHub organization to use for the release",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("ORGANIZATION"), defaults.MK(defaults.KeyOrganization)),
		Value:    utils.ProjectCalicoOrg,
	}
	repoFlagName = "repo"
	repoFlag     = &cli.StringFlag{
		Name:     repoFlagName,
		Category: gitCategory,
		Usage:    "The GitHub repository to use for the release",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("GIT_REPO"), defaults.MK(defaults.KeyGitRepo)),
		Value:    utils.CalicoRepoName,
	}
	repoRemoteFlagName = "remote"
	repoRemoteFlag     = &cli.StringFlag{
		Name:     repoRemoteFlagName,
		Category: gitCategory,
		Usage:    "The remote for the git repository",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("GIT_REMOTE"), defaults.MK(defaults.KeyGitRemote)),
		Value:    utils.DefaultRemote,
	}

	// Branch/Tag flags are flags used for branch & tag management
	releaseBranchPrefixFlagName = "release-branch-prefix"
	releaseBranchPrefixFlag     = &cli.StringFlag{
		Name:     releaseBranchPrefixFlagName,
		Category: gitCategory,
		Usage:    "The stardard prefix used to denote release branches",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("RELEASE_BRANCH_PREFIX"), defaults.MK(defaults.KeyReleaseBranchPrefix)),
		Value:    utils.DefaultReleaseBranchPrefix,
	}
	devTagSuffixFlagName = "dev-tag-suffix"
	devTagSuffixFlag     = &cli.StringFlag{
		Name:     devTagSuffixFlagName,
		Category: gitCategory,
		Usage:    "The suffix used to denote development tags",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("DEV_TAG_SUFFIX"), defaults.MK(defaults.KeyDevTagSuffix)),
		Value:    utils.DefaultDevTagSuffix,
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
	validationFlagName = "validation"
	validationFlag     = &cli.BoolWithInverseFlag{
		Name:     validationFlagName,
		Category: developmentCategory,
		Usage:    "Run validation checks",
		Sources:  cli.EnvVars("VALIDATION", "RELEASE_VALIDATION"),
		Value:    true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b {
				return nil
			}
			if c.Bool(branchCheckFlagName) {
				return fmt.Errorf("--%s must be set when --%s is set", inverseFlagName(branchCheckFlagName), inverseFlagName(validationFlagName))
			}
			// image-scan is only registered on publish commands; only enforce the
			// dependency where the flag actually exists.
			if hasFlag(c, imageScanFlagName) && c.Bool(imageScanFlagName) {
				return fmt.Errorf("--%s must be set when --%s is set", inverseFlagName(imageScanFlagName), inverseFlagName(validationFlagName))
			}
			return nil
		},
	}
	branchCheckFlagName = "branch-check"
	branchCheckFlag     = &cli.BoolWithInverseFlag{
		Name:     branchCheckFlagName,
		Category: developmentCategory,
		Usage:    "Check that the current branch is a valid branch for release",
		Sources:  cli.EnvVars("BRANCH_CHECK", "RELEASE_BRANCH_CHECK"),
		Value:    true,
	}
)

// Container image flags are flags used to control container image building and publishing
var (
	registryFlag = &cli.StringSliceFlag{
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
	// operatorGitFlags resolve the operator's org/repo/branch. Required on any
	// command that calls calico.WithOperatorGit or operator.Clone.
	operatorGitFlags = []cli.Flag{operatorOrgFlag, operatorRepoFlag, operatorBranchFlag}

	operatorBuildCommandFlags = append(slices.Clone(operatorGitFlags),
		operatorReleaseBranchPrefixFlag,
		operatorRegistryFlag, operatorImageFlag,
		operatorFlag(envBuildOperator, envReleaseOperator),
	)

	operatorPublishCommandFlags = append(slices.Clone(operatorGitFlags),
		operatorFlag(envPublishOperator, envReleaseOperator),
	)

	// Operator git flags
	operatorOrgFlagName = "operator-org"
	operatorOrgFlag     = &cli.StringFlag{
		Name:     operatorOrgFlagName,
		Category: operatorCategory,
		Usage:    "The GitHub organization to use for Tigera operator release",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("OPERATOR_ORGANIZATION"), defaults.MK(defaults.KeyOperatorOrganization)),
		Value:    operator.DefaultOrg,
	}
	operatorRepoFlagName = "operator-repo"
	operatorRepoFlag     = &cli.StringFlag{
		Name:     operatorRepoFlagName,
		Category: operatorCategory,
		Usage:    "The GitHub repository to use for Tigera operator release",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("OPERATOR_GIT_REPO"), defaults.MK(defaults.KeyOperatorGitRepo)),
		Value:    operator.DefaultRepoName,
	}
	// Branch/Tag management flags
	operatorBranchFlagName = "operator-branch"
	operatorBranchFlag     = &cli.StringFlag{
		Name:     operatorBranchFlagName,
		Category: operatorCategory,
		Usage:    "The branch to use for Tigera operator release",
		Sources:  cli.NewValueSourceChain(cli.EnvVar("OPERATOR_BRANCH"), defaults.MK(defaults.KeyOperatorBranch)),
		Value:    operator.DefaultBranch,
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

	operatorFlagName   = "operator"
	envBuildOperator   = "BUILD_OPERATOR"
	envPublishOperator = "PUBLISH_OPERATOR"
	envReleaseOperator = "RELEASE_OPERATOR"
	operatorFlag       = func(envVars ...string) *cli.BoolWithInverseFlag {
		return &cli.BoolWithInverseFlag{
			Name:     operatorFlagName,
			Category: operatorCategory,
			Usage:    "Include Tigera operator in the release steps",
			Sources:  cli.EnvVars(envVars...),
			Value:    true,
		}
	}
)

// External flags are flags used to interact with external services
var (
	// CI flags for interacting with CI services (Semaphore)
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
	notifyFlag = &cli.BoolWithInverseFlag{
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
	imageScanFlags = []cli.Flag{
		imageScanFlag,
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
	imageScanFlagName = "image-scan"
	imageScanFlag     = &cli.BoolWithInverseFlag{
		Name:     imageScanFlagName,
		Category: imageScannerCategory,
		Usage:    "Submit the image to the image scan service",
		Sources:  cli.EnvVars("RELEASE_IMAGE_SCAN"),
		Value:    true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			logrus.WithField(imageScanFlagName, b).Info("Image scanning configuration")
			if b && !imageScanningAPIConfig(c).Valid() {
				if !c.Bool(ciFlag.Name) {
					logrus.Warn("Image scanning configuration is incomplete")
				}
				return fmt.Errorf("invalid configuration for image scanning. Either set --%s and --%s or set --%s", imageScannerAPIFlag.Name, imageScannerTokenFlag.Name, inverseFlagName(imageScanFlagName))
			}
			return nil
		},
	}

	// GitHub API flags
	githubTokenFlag = &cli.StringFlag{
		Name:    "github-token",
		Usage:   "The GitHub token to use when interacting with the GitHub API",
		Sources: cli.EnvVars("GITHUB_TOKEN", "GH_TOKEN"),
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
	hashreleaseServerFlags = []cli.Flag{hashreleaseServerBucketFlag}
	publishHashreleaseFlag = &cli.BoolWithInverseFlag{
		Name:     "publish-to-hashrelease-server",
		Category: hashreleaseServerCategory,
		Usage:    "Publish the hashrelease to the hashrelease server",
		Sources:  cli.EnvVars("PUBLISH_TO_HASHRELEASE_SERVER"),
		Value:    true,
	}
	latestFlag = &cli.BoolWithInverseFlag{
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
	// Images.
	imagesFlagName          = "images"
	envBuildImages          = "BUILD_CONTAINER_IMAGES"
	envPublishImages        = "PUBLISH_IMAGES"
	envReleaseImages        = "RELEASE_IMAGES"
	archiveImagesFlagName   = "archive-images"
	envArchiveImages        = "ARCHIVE_IMAGES"
	envBuildArchiveImages   = "BUILD_IMAGES_ARCHIVE"
	envReleaseArchiveImages = "RELEASE_IMAGES_ARCHIVE"

	// Helm charts.
	helmChartsFlagName = "helm-charts"
	envBuildCharts     = "BUILD_CHARTS"
	envPublishCharts   = "PUBLISH_CHARTS"
	envReleaseCharts   = "RELEASE_CHARTS"

	// Helm index.
	helmIndexFlagName   = "helm-index"
	envHelmIndexLegacy  = "UPDATE_HELM_INDEX"
	envBuildHelmIndex   = "BUILD_HELM_INDEX"
	envPublishHelmIndex = "PUBLISH_HELM_INDEX"
	envReleaseHelmIndex = "RELEASE_HELM_INDEX"

	// Windows archive (build-only).
	windowsArchiveFlagName   = "windows-archive"
	envBuildWindowsArchive   = "BUILD_WINDOWS_ARCHIVE"
	envReleaseWindowsArchive = "RELEASE_WINDOWS_ARCHIVE"

	// Build-only.
	envBuildManifests     = "BUILD_MANIFESTS"
	envReleaseManifests   = "RELEASE_MANIFESTS"
	envBuildOCPBundle     = "BUILD_OCP_BUNDLE"
	envReleaseOCPBundle   = "RELEASE_OCP_BUNDLE"
	envBuildBinaries      = "BUILD_BINARIES"
	envReleaseBinaries    = "RELEASE_BINARIES"
	envBuildTarball       = "BUILD_TARBALL"
	envReleaseTarball     = "RELEASE_TARBALL"
	envBuildE2EBinaries   = "BUILD_E2E_BINARIES"
	envReleaseE2EBinaries = "RELEASE_E2E_BINARIES"
	envBuildReleaseNotes  = "BUILD_RELEASE_NOTES"
	envReleaseNotes       = "RELEASE_NOTES"

	// Publish-only.
	envPublishGitRefLegacy  = "PUBLISH_GIT_TAG"
	envPublishGitRef        = "PUBLISH_GIT_REF"
	envReleaseGitRef        = "RELEASE_GIT_REF"
	envPublishGithubRelease = "PUBLISH_GITHUB_RELEASE"
	envReleaseGithubRelease = "RELEASE_GITHUB_RELEASE"
)

var (
	buildStepFlags = func(hashrelease bool) []cli.Flag {
		f := []cli.Flag{
			manifestsFlag,
			ocpBundleFlag,
			imagesFlag(!hashrelease, envBuildImages, envReleaseImages),
			archiveImagesFlag(!hashrelease, envArchiveImages, envBuildArchiveImages, envReleaseArchiveImages),
			binariesFlag,
			helmChartsFlag(envBuildCharts, envReleaseCharts),
			helmIndexFlag(envHelmIndexLegacy, envBuildHelmIndex, envReleaseHelmIndex),
			tarballFlag,
			windowsArchiveFlag(envBuildWindowsArchive, envReleaseWindowsArchive),
		}
		if hashrelease {
			f = append(f, e2eBinariesFlag, releaseNotesFlag)
		}
		return f
	}
	publishStepFlags = func(hashrelease bool) []cli.Flag {
		f := []cli.Flag{
			imagesFlag(!hashrelease, envPublishImages, envReleaseImages),
			helmChartsFlag(envPublishCharts, envReleaseCharts),
		}
		if hashrelease {
			return f
		}
		return append(f,
			helmIndexFlag(envHelmIndexLegacy, envPublishHelmIndex, envReleaseHelmIndex),
			gitRefFlag,
			githubReleaseFlag)
	}

	imagesFlag = func(value bool, envVars ...string) *cli.BoolWithInverseFlag {
		return &cli.BoolWithInverseFlag{
			Name:     imagesFlagName,
			Category: stepControlCategory,
			Usage:    "Include container images in the release step",
			Sources:  cli.EnvVars(envVars...),
			Value:    value,
			Action: func(_ context.Context, c *cli.Command, b bool) error {
				// archive-images is build-only; only enforce the dependency
				// where the flag is registered. The "images on but not
				// archived" warning is emitted from archiveImagesFlag.Action
				// instead so it doesn't fire on publish commands where
				// archive-images doesn't exist.
				if hasFlag(c, archiveImagesFlagName) && !b && c.Bool(archiveImagesFlagName) {
					return fmt.Errorf("cannot archive images without building them; use --%s flag to build images", imagesFlagName)
				}
				return nil
			},
		}
	}
	archiveImagesFlag = func(value bool, envVars ...string) *cli.BoolWithInverseFlag {
		return &cli.BoolWithInverseFlag{
			Name:     archiveImagesFlagName,
			Category: stepControlCategory,
			Usage:    "Archive container images in the release tarball",
			Sources:  cli.EnvVars(envVars...),
			Value:    value,
			Action: func(_ context.Context, c *cli.Command, b bool) error {
				if b && !c.Bool(imagesFlagName) {
					return fmt.Errorf("cannot archive images without building them; use --%s flag to build images", imagesFlagName)
				}
				if !b && c.Bool(imagesFlagName) {
					logrus.Warnf("Images are included but not archived; to include images in the archive set --%s", archiveImagesFlagName)
				}
				return nil
			},
		}
	}
	helmChartsFlag = func(envVars ...string) *cli.BoolWithInverseFlag {
		return &cli.BoolWithInverseFlag{
			Name:     helmChartsFlagName,
			Category: stepControlCategory,
			Usage:    "Include Helm charts in the release step",
			Sources:  cli.EnvVars(envVars...),
			Value:    true,
			Action: func(_ context.Context, c *cli.Command, b bool) error {
				if b {
					return nil
				}
				if c.Bool(helmIndexFlagName) {
					return fmt.Errorf("--%s must be set when --%s is set", inverseFlagName(helmIndexFlagName), inverseFlagName(helmChartsFlagName))
				}
				return nil
			},
		}
	}
	helmIndexFlag = func(envVars ...string) *cli.BoolWithInverseFlag {
		return &cli.BoolWithInverseFlag{
			Name:     helmIndexFlagName,
			Category: stepControlCategory,
			Usage:    "Build/update the Helm chart index",
			Sources:  cli.EnvVars(envVars...),
			Value:    true,
		}
	}
	binariesFlag = &cli.BoolWithInverseFlag{
		Name:     "binaries",
		Category: stepControlCategory,
		Usage:    "Include binaries in the release step",
		Sources:  cli.EnvVars(envBuildBinaries, envReleaseBinaries),
		Value:    true,
	}
	e2eBinariesFlag = &cli.BoolWithInverseFlag{
		Name:     "e2e-binaries",
		Category: stepControlCategory,
		Usage:    "Build multi-arch e2e test binaries",
		Sources:  cli.EnvVars(envBuildE2EBinaries, envReleaseE2EBinaries),
		Value:    true,
	}
	releaseNotesFlag = &cli.BoolWithInverseFlag{
		Name:     "release-notes",
		Category: stepControlCategory,
		Usage:    "Generate release notes",
		Sources:  cli.EnvVars(envBuildReleaseNotes, envReleaseNotes),
		Value:    true,
	}
	manifestsFlag = &cli.BoolWithInverseFlag{
		Name:     "manifests",
		Category: stepControlCategory,
		Usage:    "Include manifests in the release step",
		Sources:  cli.EnvVars(envBuildManifests, envReleaseManifests),
		Value:    true,
	}
	ocpBundleFlag = &cli.BoolWithInverseFlag{
		Name:     "ocp-bundle",
		Category: stepControlCategory,
		Usage:    "Include OCP bundle in the release step",
		Sources:  cli.EnvVars(envBuildOCPBundle, envReleaseOCPBundle),
		Value:    true,
	}
	windowsArchiveFlag = func(envVars ...string) *cli.BoolWithInverseFlag {
		return &cli.BoolWithInverseFlag{
			Name:     windowsArchiveFlagName,
			Category: stepControlCategory,
			Usage:    "Include Windows archive in the release step",
			Sources:  cli.EnvVars(envVars...),
			Value:    true,
		}
	}
	tarballFlag = &cli.BoolWithInverseFlag{
		Name:     "tarball",
		Category: stepControlCategory,
		Usage:    "Include the release tarball in the release step",
		Sources:  cli.EnvVars(envBuildTarball, envReleaseTarball),
		Value:    true,
	}
	gitRefFlag = &cli.BoolWithInverseFlag{
		Name:     "git-ref",
		Category: stepControlCategory,
		Usage:    "Push the git ref(s) to the remote",
		Sources:  cli.EnvVars(envPublishGitRefLegacy, envPublishGitRef, envReleaseGitRef),
		Value:    true,
	}
	githubReleaseFlag = &cli.BoolWithInverseFlag{
		Name:     "github-release",
		Category: stepControlCategory,
		Usage:    "Publish the GitHub release",
		Sources:  cli.EnvVars(envPublishGithubRelease, envReleaseGithubRelease),
		Value:    true,
		Action: func(_ context.Context, c *cli.Command, b bool) error {
			if b && c.String(githubTokenFlag.Name) == "" {
				return fmt.Errorf("GitHub token is required to publish release")
			}
			return nil
		},
	}
)

func inverseFlagName(name string) string {
	return "no-" + name
}

// hasFlag reports whether the command has a flag registered under the given
// name (or one of its aliases). Used by cross-flag Action callbacks to skip
// dependency checks against flags that aren't registered on the current
// command (e.g. image-scan is publish-only).
func hasFlag(c *cli.Command, name string) bool {
	return slices.ContainsFunc(c.Flags, func(f cli.Flag) bool {
		return slices.Contains(f.Names(), name)
	})
}
