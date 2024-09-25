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

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/controller/branch"
	"github.com/projectcalico/calico/release/pkg/controller/operator"
	"github.com/projectcalico/calico/release/pkg/controller/release"
	"github.com/projectcalico/calico/release/pkg/tasks"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

const (
	skipValidationFlag  = "skip-validation"
	skipImageScanFlag   = "skip-image-scan"
	skipBranchCheckFlag = "skip-branch-check"
	publishBranchFlag   = "git-publish"
	buildImagesFlag     = "build-images"

	imageRegistryFlag = "dev-registry"

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
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip all pre-build validation", Value: false},
				&cli.BoolFlag{Name: skipBranchCheckFlag, Usage: "Skip branch checking in pre-build validation", Value: false},
				&cli.BoolFlag{Name: buildImagesFlag, Usage: "Build images from local codebase. If false, will use images from CI instead.", Value: false},
				&cli.StringFlag{Name: imageRegistryFlag, Usage: "Specify image registry to use, for development", Value: ""},
			},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-build.log")
				if !c.Bool(skipValidationFlag) {
					tasks.PreReleaseValidate(cfg, !c.Bool(skipBranchCheckFlag))
				}

				// Create the pinned-version.yaml file and extract the versions and hash.
				ver, operatorVer, hash := tasks.PinnedVersion(cfg)

				// Check if the hashrelease has already been published.
				tasks.CheckIfHashReleasePublished(cfg, hash)

				// Build the operator.
				o := operator.NewController(
					operator.WithRepoRoot(cfg.OperatorConfig.Dir),
					operator.IsHashRelease(),
					operator.WithVersion(operatorVer),
					operator.WithArchitectures(cfg.Arches),
					operator.WithValidate(!c.Bool(skipValidationFlag)),
				)
				if err := o.Build(cfg.TmpFolderPath()); err != nil {
					return err
				}

				// Configure a release builder using the generated versions, and use it
				// to build a Calico release.
				opts := []release.Option{
					release.WithRepoRoot(cfg.RepoRootDir),
					release.IsHashRelease(),
					release.WithVersions(ver, operatorVer),
					release.WithOutputDir(dir),
					release.WithBuildImages(c.Bool(buildImagesFlag)),
					release.WithPreReleaseValidation(!c.Bool(skipValidationFlag)),
					release.WithGithubOrg(cfg.Organization),
					release.WithArchitectures(cfg.Arches),
				}
				if reg := c.String(imageRegistryFlag); reg != "" {
					opts = append(opts, release.WithImageRegistries([]string{reg}))
				}

				r := release.NewController(opts...)
				if err := r.Build(); err != nil {
					return err
				}

				// For real releases, release notes are generated prior to building the release. For hash releases,
				// generate a set of release notes and add them to the hashrelease directory.
				tasks.ReleaseNotes(cfg, filepath.Join(dir, releaseNotesDir), version.New(ver))

				// Adjsut the formatting of the generated outputs to match the legacy hashrelease format.
				return tasks.ReformatHashrelease(cfg, dir)
			},
		},

		// The publish command is used to publish a locally built hashrelease to the hashrelease server.
		{
			Name:  "publish",
			Usage: "Publish hashrelease from _output/ to hashrelease server",
			Flags: []cli.Flag{
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

				// Push the operator hashrelease first before validaion
				// This is because validation checks all images exists and sends to Image Scan Service
				o := operator.NewController(
					operator.WithRepoRoot(cfg.OperatorConfig.Dir),
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
				tasks.HashreleasePush(cfg, dir)
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
			Action: func(c *cli.Context) error {
				configureLogging("release-notes.log")
				ver, err := version.DetermineReleaseVersion(version.GitVersion(cfg.RepoRootDir), cfg.DevTagSuffix)
				if err != nil {
					return err
				}
				tasks.ReleaseNotes(cfg, filepath.Join(cfg.RepoRootDir, releaseNotesDir), ver)
				return nil
			},
		},

		// Build a release.
		{
			Name:  "build",
			Usage: "Build an official Calico release",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.StringFlag{Name: imageRegistryFlag, Usage: "Specify image registry to use, for development", Value: ""},
			},
			Action: func(c *cli.Context) error {
				configureLogging("release-build.log")

				// Determine the versions to use for the release.
				ver, err := version.DetermineReleaseVersion(version.GitVersion(cfg.RepoRootDir), cfg.DevTagSuffix)
				if err != nil {
					return err
				}
				operatorVer, err := version.DetermineOperatorVersion(cfg.RepoRootDir)
				if err != nil {
					return err
				}

				// Configure the builder.
				opts := []release.Option{
					release.WithRepoRoot(cfg.RepoRootDir),
					release.WithVersions(ver.FormattedString(), operatorVer.FormattedString()),
					release.WithOutputDir(filepath.Join(baseUploadDir, ver.FormattedString())),
					release.WithArchitectures(cfg.Arches),
					release.WithGithubOrg(cfg.Organization),
				}
				if c.Bool(skipValidationFlag) {
					opts = append(opts, release.WithPreReleaseValidation(false))
				}
				if reg := c.String(imageRegistryFlag); reg != "" {
					opts = append(opts, release.WithImageRegistries([]string{reg}))
				}
				r := release.NewController(opts...)
				return r.Build()
			},
		},

		// Publish a release.
		{
			Name:  "publish",
			Usage: "Publish a pre-built Calico release",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipPublishImagesFlag, Usage: "Skip publishing of container images to registry", Value: false},
				&cli.BoolFlag{Name: skipPublishGitTag, Usage: "Skip publishing of tag to git repository", Value: false},
				&cli.BoolFlag{Name: skipPublishGithubRelease, Usage: "Skip publishing of release to Github", Value: false},
				&cli.StringFlag{Name: imageRegistryFlag, Usage: "Specify image registry to use, for development", Value: ""},
			},
			Action: func(c *cli.Context) error {
				configureLogging("release-publish.log")
				ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
				if err != nil {
					return err
				}
				opts := []release.Option{
					release.WithRepoRoot(cfg.RepoRootDir),
					release.WithVersions(ver.FormattedString(), operatorVer.FormattedString()),
					release.WithOutputDir(filepath.Join(baseUploadDir, ver.FormattedString())),
					release.WithPublishOptions(!c.Bool(skipPublishImagesFlag), !c.Bool(skipPublishGitTag), !c.Bool(skipPublishGithubRelease)),
					release.WithGithubOrg(cfg.Organization),
				}
				if reg := c.String(imageRegistryFlag); reg != "" {
					opts = append(opts, release.WithImageRegistries([]string{reg}))
				}
				r := release.NewController(opts...)
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
				controller := branch.NewController(branch.WithRepoRoot(cfg.RepoRootDir),
					branch.WithRepoRemote(cfg.GitRemote),
					branch.WithMainBranch(utils.DefaultBranch),
					branch.WithDevTagIdentifier(cfg.DevTagSuffix),
					branch.WithReleaseBranchPrefix(cfg.RepoReleaseBranchPrefix),
					branch.WithValidate(!c.Bool(skipValidationFlag)),
					branch.WithPublish(c.Bool(publishBranchFlag)))
				return controller.CutBranch()
			},
		},
		// Cut a new operator release branch
		{
			Name:  "cut-operator",
			Usage: fmt.Sprintf("Cut a new operator release branch from %s", utils.DefaultBranch),
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip release branch cut validations", Value: false},
				&cli.BoolFlag{Name: publishBranchFlag, Usage: "Push branch and tag to git. If false, all changes are local.", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging("cut-operator-branch.log")
				controller := operator.NewController(
					operator.WithRepoRoot(cfg.OperatorConfig.Dir),
					operator.WithRepoRemote(cfg.OperatorConfig.GitRemote),
					operator.WithRepoOrganization(cfg.OperatorConfig.GitOrganization),
					operator.WithRepoName(cfg.OperatorConfig.GitRepository),
					operator.WithMainBranch(utils.DefaultBranch),
					operator.WithDevTagIdentifier(cfg.OperatorConfig.DevTagSuffix),
					operator.WithReleaseBranchPrefix(cfg.OperatorConfig.RepoReleaseBranchPrefix),
					operator.WithValidate(!c.Bool(skipValidationFlag)),
					operator.WithPublish(c.Bool(publishBranchFlag)),
				)
				return controller.CutBranch()
			},
		},
	}
}
