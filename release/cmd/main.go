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
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/cmd/flags"
	"github.com/projectcalico/calico/release/cmd/hashrelease"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/logger"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

const (
	latestFlag          = "latest"
	skipValidationFlag  = "skip-validation"
	skipImageScanFlag   = "skip-image-scan"
	skipBranchCheckFlag = "skip-branch-check"
	publishBranchFlag   = "git-publish"
	buildImagesFlag     = "build-images"

	orgFlag  = "org"
	repoFlag = "repo"

	imageRegistryFlag = "registry"

	operatorOrgFlag      = "operator-org"
	operatorRepoFlag     = "operator-repo"
	operatorImageFlag    = "operator-image"
	operatorRegistryFlag = "operator-registry"

	sourceBranchFlag = "source-branch"
	newBranchFlag    = "new-branch-version"

	// Configuration flags for the release publish command.
	skipPublishImagesFlag        = "skip-publish-images"
	skipPublishGitTagFlag        = "skip-publish-git-tag"
	skipPublishGithubReleaseFlag = "skip-publish-github-release"
	skipPublishHashreleaseFlag   = "skip-publish-hashrelease-server"
)

// debug controls whether or not to emit debug level logging.
var debug bool

func main() {
	cfg := config.LoadConfig()

	app := &cli.App{
		Name:     "release",
		Usage:    fmt.Sprintf("a tool for building %s releases", utils.DisplayProductName()),
		Flags:    flags.GlobalFlags(),
		Commands: []*cli.Command{},
	}

	// Add sub-commands below.

	// The hashrelease command suite is used to build and publish hashreleases, as well as
	// to interact with the hashrelease server.
	app.Commands = append(app.Commands, hashrelease.Command(utils.Calico, cfg))

	// The release command suite is used to build and publish official Calico releases.
	app.Commands = append(app.Commands, &cli.Command{
		Name:        "release",
		Aliases:     []string{"rel"},
		Usage:       "Build and publish official Calico releases.",
		Subcommands: releaseSubCommands(cfg),
	})

	// The branch command suite manages branches.
	app.Commands = append(app.Commands, &cli.Command{
		Name:        "branch",
		Aliases:     []string{"br"},
		Usage:       "Manage branches.",
		Subcommands: branchSubCommands(cfg),
	})

	// Run the app.
	if err := app.Run(os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running task")
	}
}

func releaseSubCommands(cfg *config.Config) []*cli.Command {
	// Base location for release uploads. Each release will get a directory
	// within this location.
	baseUploadDir := filepath.Join(cfg.RepoRootDir, "release", "_output", "upload")

	return []*cli.Command{
		// Build release notes prior to a release.
		{
			Name:  "generate-release-notes",
			Usage: "Generate release notes for the next release",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: orgFlag, Usage: "Git organization", EnvVars: []string{"ORGANIZATION"}, Value: config.DefaultOrg},
			},
			Action: func(c *cli.Context) error {
				logger.Configure("release-notes.log", debug)
				ver, err := version.DetermineReleaseVersion(version.GitVersion(), cfg.DevTagSuffix)
				if err != nil {
					return err
				}
				filePath, err := outputs.ReleaseNotes(c.String(orgFlag), cfg.GithubToken, cfg.RepoRootDir, cfg.RepoRootDir, ver)
				if err != nil {
					logrus.WithError(err).Fatal("Failed to generate release notes")
				}
				logrus.WithField("file", filePath).Info("Generated release notes")
				logrus.Info("Please review for accuracy, and format appropriately before releasing.")
				return nil
			},
		},

		// Build a release.
		{
			Name:  "build",
			Usage: "Build an official Calico release",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: orgFlag, Usage: "Git organization", EnvVars: []string{"ORGANIZATION"}, Value: config.DefaultOrg},
				&cli.StringFlag{Name: repoFlag, Usage: "Git repository", EnvVars: []string{"GIT_REPO"}, Value: config.DefaultRepo},
				&cli.BoolFlag{Name: buildImagesFlag, Usage: "Build images from local codebase. If false, will use images from CI instead.", EnvVars: []string{"BUILD_CONTAINER_IMAGES"}, Value: true},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.StringSliceFlag{Name: imageRegistryFlag, Usage: "Specify image registry or registries to use", EnvVars: []string{"REGISTRIES"}, Value: &cli.StringSlice{}},
			},
			Action: func(c *cli.Context) error {
				logger.Configure("release-build.log", debug)

				// Determine the versions to use for the release.
				ver, err := version.DetermineReleaseVersion(version.GitVersion(), cfg.DevTagSuffix)
				if err != nil {
					return err
				}
				operatorVer, err := version.DetermineOperatorVersion(cfg.RepoRootDir)
				if err != nil {
					return err
				}

				// Configure the builder.
				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(cfg.RepoReleaseBranchPrefix),
					calico.WithVersions(&version.Data{
						ProductVersion:  ver,
						OperatorVersion: operatorVer,
					}),
					calico.WithOutputDir(filepath.Join(baseUploadDir, ver.FormattedString())),
					calico.WithArchitectures(cfg.Arches),
					calico.WithGithubOrg(c.String(orgFlag)),
					calico.WithRepoName(c.String(repoFlag)),
					calico.WithRepoRemote(cfg.GitRemote),
					calico.WithBuildImages(c.Bool(buildImagesFlag)),
				}
				if c.Bool(skipValidationFlag) {
					opts = append(opts, calico.WithValidate(false))
				}
				if reg := c.StringSlice(imageRegistryFlag); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				r := calico.NewManager(opts...)
				return r.Build()
			},
		},

		// Publish a release.
		{
			Name:  "publish",
			Usage: "Publish a pre-built Calico release",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: orgFlag, Usage: "Git organization", EnvVars: []string{"ORGANIZATION"}, Value: config.DefaultOrg},
				&cli.StringFlag{Name: repoFlag, Usage: "Git repository", EnvVars: []string{"GIT_REPO"}, Value: config.DefaultRepo},
				&cli.BoolFlag{Name: skipPublishImagesFlag, Usage: "Skip publishing of container images to registry", EnvVars: []string{"SKIP_PUBLISH_IMAGES"}, Value: false},
				&cli.BoolFlag{Name: skipPublishGitTagFlag, Usage: "Skip publishing of tag to git repository", Value: false},
				&cli.BoolFlag{Name: skipPublishGithubReleaseFlag, Usage: "Skip publishing of release to Github", Value: false},
				&cli.StringSliceFlag{Name: imageRegistryFlag, Usage: "Specify image registry or registries to use", EnvVars: []string{"REGISTRIES"}, Value: &cli.StringSlice{}},
			},
			Action: func(c *cli.Context) error {
				logger.Configure("release-publish.log", debug)

				ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
				if err != nil {
					return err
				}
				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithVersions(&version.Data{
						ProductVersion:  ver,
						OperatorVersion: operatorVer,
					}),
					calico.WithOutputDir(filepath.Join(baseUploadDir, ver.FormattedString())),
					calico.WithGithubOrg(c.String(orgFlag)),
					calico.WithRepoName(c.String(repoFlag)),
					calico.WithRepoRemote(cfg.GitRemote),
					calico.WithPublishImages(!c.Bool(skipPublishImagesFlag)),
					calico.WithPublishGitTag(!c.Bool(skipPublishGitTagFlag)),
					calico.WithPublishGithubRelease(!c.Bool(skipPublishGithubReleaseFlag)),
				}
				if reg := c.StringSlice(imageRegistryFlag); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				r := calico.NewManager(opts...)
				return r.PublishRelease()
			},
		},
	}
}

func branchSubCommands(cfg *config.Config) []*cli.Command {
	return []*cli.Command{
		// Cut a new release branch
		{
			Name:  "cut",
			Usage: fmt.Sprintf("Cut a new release branch from %s", utils.DefaultBranch),
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip release branch cut validations", Value: false},
				&cli.BoolFlag{Name: publishBranchFlag, Usage: "Push branch and tag to git. If false, all changes are local.", Value: false},
			},
			Action: func(c *cli.Context) error {
				logger.Configure("cut-branch.log", debug)
				m := branch.NewManager(branch.WithRepoRoot(cfg.RepoRootDir),
					branch.WithRepoRemote(cfg.GitRemote),
					branch.WithMainBranch(utils.DefaultBranch),
					branch.WithDevTagIdentifier(cfg.DevTagSuffix),
					branch.WithReleaseBranchPrefix(cfg.RepoReleaseBranchPrefix),
					branch.WithValidate(!c.Bool(skipValidationFlag)),
					branch.WithPublish(c.Bool(publishBranchFlag)))
				return m.CutReleaseBranch()
			},
		},
		// Cut a new operator release branch
		{
			Name:  "cut-operator",
			Usage: fmt.Sprintf("Cut a new operator release branch from %s", utils.DefaultBranch),
			Flags: []cli.Flag{
				&cli.StringFlag{Name: operatorOrgFlag, Usage: "Operator git organization", EnvVars: []string{"OPERATOR_GIT_ORGANIZATION"}, Value: config.OperatorDefaultOrg},
				&cli.StringFlag{Name: operatorRepoFlag, Usage: "Operator git repository", EnvVars: []string{"OPERATOR_GIT_REPO"}, Value: config.OperatorDefaultRepo},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip release branch cut validations", Value: false},
				&cli.BoolFlag{Name: publishBranchFlag, Usage: "Push branch and tag to git. If false, all changes are local.", Value: false},
				&cli.StringFlag{Name: sourceBranchFlag, Usage: "The branch to cut the operator release from", Value: utils.DefaultBranch},
				&cli.StringFlag{Name: newBranchFlag, Usage: fmt.Sprintf("The new version for the branch to create i.e. vX.Y to create a %s-vX.Y branch", cfg.Operator.RepoReleaseBranchPrefix), Value: ""},
			},
			Action: func(c *cli.Context) error {
				logger.Configure("cut-operator-branch.log", debug)
				if c.String(newBranchFlag) == "" {
					logrus.Warn("No branch version specified, will cut branch based on latest dev tag")
				}
				// Clone the operator repository
				if err := utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", c.String(operatorOrgFlag), c.String(operatorRepoFlag)), cfg.Operator.Branch, cfg.Operator.Dir); err != nil {
					return err
				}
				// Create operator manager
				m := operator.NewManager(
					operator.WithOperatorDirectory(cfg.Operator.Dir),
					operator.WithRepoRemote(cfg.Operator.GitRemote),
					operator.WithGithubOrg(c.String(operatorOrgFlag)),
					operator.WithRepoName(c.String(operatorRepoFlag)),
					operator.WithBranch(utils.DefaultBranch),
					operator.WithDevTagIdentifier(cfg.Operator.DevTagSuffix),
					operator.WithReleaseBranchPrefix(cfg.Operator.RepoReleaseBranchPrefix),
					operator.WithValidate(!c.Bool(skipValidationFlag)),
					operator.WithPublish(c.Bool(publishBranchFlag)),
				)
				return m.CutBranch(c.String(newBranchFlag))
			},
		},
	}
}
