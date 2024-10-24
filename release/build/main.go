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
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
	"github.com/projectcalico/calico/release/pkg/tasks"
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
	skipPublishImagesFlag    = "skip-publish-images"
	skipPublishGitTag        = "skip-publish-git-tag"
	skipPublishGithubRelease = "skip-publish-github-release"
)

var (
	// debug controls whether or not to emit debug level logging.
	debug bool

	// hashreleaseDir is the directory where hashreleases are built relative to the repo root.
	hashreleaseDir = []string{"release", "_output", "hashrelease"}

	// releaseNotesDir is the directory where release notes are stored
	releaseNotesDir = "release-notes"
)

func configureLogging(filename string) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Set up logging to both stdout as well as a file.
	writers := []io.Writer{os.Stdout, &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
	}}
	logrus.SetOutput(io.MultiWriter(writers...))
}

// globalFlags are flags that are available to all sub-commands.
var globalFlags = []cli.Flag{
	&cli.BoolFlag{
		Name:        "debug",
		Aliases:     []string{"d"},
		Usage:       "Enable verbose log output",
		Value:       false,
		Destination: &debug,
	},
}

func main() {
	cfg := config.LoadConfig()

	app := &cli.App{
		Name:     "release",
		Usage:    fmt.Sprintf("a tool for building %s releases", utils.DisplayProductName()),
		Flags:    globalFlags,
		Commands: []*cli.Command{},
	}

	// Add sub-commands below.

	// The hashrelease command suite is used to build and publish hashreleases, as well as
	// to interact with the hashrelease server.
	app.Commands = append(app.Commands, &cli.Command{
		Name:        "hashrelease",
		Aliases:     []string{"hr"},
		Usage:       "Build and publish hashreleases.",
		Subcommands: hashreleaseSubCommands(cfg),
	})

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

func hashreleaseSubCommands(cfg *config.Config) []*cli.Command {
	// dir is the directory where hashreleases are built.
	dir := filepath.Join(append([]string{cfg.RepoRootDir}, hashreleaseDir...)...)

	return []*cli.Command{
		// The build command is used to produce a new local hashrelease in the output directory.
		{
			Name:  "build",
			Usage: "Build a hashrelease locally in _output/",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: orgFlag, Usage: "Git organization", EnvVars: []string{"ORGANIZATION"}, Value: config.DefaultOrg},
				&cli.StringFlag{Name: repoFlag, Usage: "Git repository", EnvVars: []string{"GIT_REPO"}, Value: config.DefaultRepo},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip all pre-build validation", Value: false},
				&cli.BoolFlag{Name: skipBranchCheckFlag, Usage: "Skip check that this is a valid release branch.", Value: false},
				&cli.BoolFlag{Name: buildImagesFlag, Usage: "Build images from local codebase. If false, will use images from CI instead.", Value: false},
				&cli.StringFlag{Name: imageRegistryFlag, Usage: "Specify image registry to use", Value: ""},
				&cli.StringFlag{Name: operatorOrgFlag, Usage: "Operator git organization", EnvVars: []string{"OPERATOR_GIT_ORGANIZATION"}, Value: config.OperatorDefaultOrg},
				&cli.StringFlag{Name: operatorRepoFlag, Usage: "Operator git repository", EnvVars: []string{"OPERATOR_GIT_REPO"}, Value: config.OperatorDefaultRepo},
				&cli.StringFlag{Name: operatorImageFlag, Usage: "Specify the operator image to use", EnvVars: []string{"OPERATOR_IMAGE"}, Value: config.OperatorDefaultImage},
				&cli.StringFlag{Name: operatorRegistryFlag, Usage: "Specify the operator registry to use", EnvVars: []string{"OPERATOR_REGISTRY"}, Value: registry.QuayRegistry},
			},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-build.log")
				if c.Bool(skipValidationFlag) && !c.Bool(skipBranchCheckFlag) {
					return fmt.Errorf("%s must be set if %s is set", skipBranchCheckFlag, skipValidationFlag)
				}
				if c.String(imageRegistryFlag) != "" && c.String(operatorRegistryFlag) == "" {
					return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag, imageRegistryFlag)
				}
				if c.String(operatorImageFlag) != "" && c.String(operatorRegistryFlag) == "" {
					return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag, operatorImageFlag)
				} else if c.String(operatorRegistryFlag) != "" && c.String(operatorImageFlag) == "" {
					return fmt.Errorf("%s must be set if %s is set", operatorImageFlag, operatorRegistryFlag)
				}
				if !cfg.CI.IsCI {
					if c.String(imageRegistryFlag) == "" && c.Bool(buildImagesFlag) {
						logrus.Warn("Local builds should specify an image registry using the --dev-registry flag")
					}
					if c.String(operatorRegistryFlag) == registry.QuayRegistry && c.String(operatorImageFlag) == config.OperatorDefaultImage {
						logrus.Warn("Local builds should specify an operator image and registry using the --operator-image and --operator-registry flags")
					}
				}

				// Clone the operator repository
				if err := utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", c.String(operatorOrgFlag), c.String(operatorRepoFlag)), cfg.Operator.Branch, cfg.Operator.Dir); err != nil {
					return err
				}

				// Create the pinned-version.yaml file and extract the versions and hash.
				pinnedCfg := pinnedversion.Config{
					RootDir:             cfg.RepoRootDir,
					ReleaseBranchPrefix: cfg.RepoReleaseBranchPrefix,
					Operator:            cfg.Operator,
				}
				if c.String(operatorImageFlag) != "" {
					pinnedCfg.Operator.Image = c.String(operatorImageFlag)
				}
				if c.String(operatorRegistryFlag) != "" {
					pinnedCfg.Operator.Registry = c.String(operatorRegistryFlag)
				}
				_, data, err := pinnedversion.GeneratePinnedVersionFile(pinnedCfg, cfg.TmpFolderPath())
				if err != nil {
					return err
				}

				versions := &version.Data{
					ProductVersion:  version.New(data.ProductVersion),
					OperatorVersion: version.New(data.Operator.Version),
				}

				// Check if the hashrelease has already been published.
				if published, err := tasks.HashreleasePublished(cfg, data.Hash); err != nil {
					return err
				} else if published {
					// On CI, we want it to fail if the hashrelease has already been published.
					// However, on local builds, we just log a warning and continue.
					if cfg.CI.IsCI {
						return fmt.Errorf("hashrelease %s has already been published", data.Hash)
					} else {
						logrus.Warnf("hashrelease %s has already been published", data.Hash)
					}
				}

				// Build the operator
				operatorOpts := []operator.Option{
					operator.WithOperatorDirectory(cfg.Operator.Dir),
					operator.WithReleaseBranchPrefix(cfg.RepoReleaseBranchPrefix),
					operator.IsHashRelease(),
					operator.WithArchitectures(cfg.Arches),
					operator.WithValidate(!c.Bool(skipValidationFlag)),
					operator.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag)),
					operator.WithVersion(versions.OperatorVersion.FormattedString()),
				}
				o := operator.NewManager(operatorOpts...)
				if err := o.Build(cfg.TmpFolderPath()); err != nil {
					return err
				}

				// Configure a release builder using the generated versions, and use it
				// to build a Calico release.
				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(cfg.RepoReleaseBranchPrefix),
					calico.IsHashRelease(),
					calico.WithVersions(versions),
					calico.WithOutputDir(dir),
					calico.WithBuildImages(c.Bool(buildImagesFlag)),
					calico.WithValidate(!c.Bool(skipValidationFlag)),
					calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag)),
					calico.WithGithubOrg(c.String(orgFlag)),
					calico.WithRepoName(c.String(repoFlag)),
					calico.WithRepoRemote(cfg.GitRemote),
					calico.WithArchitectures(cfg.Arches),
				}
				if reg := c.String(imageRegistryFlag); reg != "" {
					opts = append(opts, calico.WithImageRegistries([]string{reg}))
				}

				r := calico.NewManager(opts...)
				if err := r.Build(); err != nil {
					return err
				}

				// For real releases, release notes are generated prior to building the release. For hash releases,
				// generate a set of release notes and add them to the hashrelease directory.
				if _, err := outputs.ReleaseNotes(c.String(orgFlag), cfg.GithubToken, cfg.RepoRootDir, filepath.Join(dir, releaseNotesDir), versions.ProductVersion); err != nil {
					return err
				}

				// Adjsut the formatting of the generated outputs to match the legacy hashrelease format.
				return tasks.ReformatHashrelease(cfg, dir)
			},
		},

		// The publish command is used to publish a locally built hashrelease to the hashrelease server.
		{
			Name:  "publish",
			Usage: "Publish hashrelease from _output/ to hashrelease server",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: latestFlag, Usage: "Promote this release as the latest for this stream", Value: true},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.BoolFlag{Name: skipImageScanFlag, Usage: "Skip sending images to image scan service.", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-publish.log")

				// If skipValidationFlag is set, then we will also skip the image scan. Ensure the user
				// has set the correct flags.
				if c.Bool(skipValidationFlag) && !c.Bool(skipImageScanFlag) {
					return fmt.Errorf("%s must be set if %s is set", skipImageScanFlag, skipValidationFlag)
				}

				// Extract the version from pinned-version.yaml.
				hash, err := pinnedversion.RetrievePinnedVersionHash(cfg.TmpFolderPath())
				if err != nil {
					return err
				}

				// Check if the hashrelease has already been published.
				if published, err := tasks.HashreleasePublished(cfg, hash); err != nil {
					return err
				} else if published {
					return fmt.Errorf("hashrelease %s has already been published", hash)
				}

				// Push the operator hashrelease first before validaion
				// This is because validation checks all images exists and sends to Image Scan Service
				o := operator.NewManager(
					operator.WithOperatorDirectory(cfg.Operator.Dir),
					operator.IsHashRelease(),
					operator.WithArchitectures(cfg.Arches),
					operator.WithValidate(!c.Bool(skipValidationFlag)),
				)
				if err := o.Publish(cfg.TmpFolderPath()); err != nil {
					return err
				}
				if !c.Bool(skipValidationFlag) {
					tasks.HashreleaseValidate(cfg, c.Bool(skipImageScanFlag))
				}
				tasks.HashreleasePush(cfg, dir, c.Bool(latestFlag))
				return nil
			},
		},

		// The garbage-collect command is used to clean up older hashreleases from the hashrelease server.
		{
			Name:    "garbage-collect",
			Usage:   "Clean up older hashreleases",
			Aliases: []string{"gc"},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-garbage-collect.log")
				tasks.HashreleaseCleanRemote(cfg)
				return nil
			},
		},
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
				configureLogging("release-notes.log")
				ver, err := version.DetermineReleaseVersion(version.GitVersion(), cfg.DevTagSuffix)
				if err != nil {
					return err
				}
				filePath, err := outputs.ReleaseNotes(c.String(orgFlag), cfg.GithubToken, cfg.RepoRootDir, filepath.Join(cfg.RepoRootDir, releaseNotesDir), ver)
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
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.StringFlag{Name: imageRegistryFlag, Usage: "Specify image registry to use", Value: ""},
			},
			Action: func(c *cli.Context) error {
				configureLogging("release-build.log")

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
				}
				if c.Bool(skipValidationFlag) {
					opts = append(opts, calico.WithValidate(false))
				}
				if reg := c.String(imageRegistryFlag); reg != "" {
					opts = append(opts, calico.WithImageRegistries([]string{reg}))
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
				&cli.BoolFlag{Name: skipPublishImagesFlag, Usage: "Skip publishing of container images to registry", Value: false},
				&cli.BoolFlag{Name: skipPublishGitTag, Usage: "Skip publishing of tag to git repository", Value: false},
				&cli.BoolFlag{Name: skipPublishGithubRelease, Usage: "Skip publishing of release to Github", Value: false},
				&cli.StringFlag{Name: imageRegistryFlag, Usage: "Specify image registry to use", Value: ""},
			},
			Action: func(c *cli.Context) error {
				configureLogging("release-publish.log")
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
					calico.WithPublishOptions(!c.Bool(skipPublishImagesFlag), !c.Bool(skipPublishGitTag), !c.Bool(skipPublishGithubRelease)),
					calico.WithGithubOrg(c.String(orgFlag)),
					calico.WithRepoName(c.String(repoFlag)),
					calico.WithRepoRemote(cfg.GitRemote),
				}
				if reg := c.String(imageRegistryFlag); reg != "" {
					opts = append(opts, calico.WithImageRegistries([]string{reg}))
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
				configureLogging("cut-branch.log")
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
				configureLogging("cut-operator-branch.log")
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
