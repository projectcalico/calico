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
	"strings"

	"github.com/coreos/go-semver/semver"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/builder"
	"github.com/projectcalico/calico/release/pkg/tasks"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

const (
	skipValidationFlag  = "skip-validation"
	skipImageScanFlag   = "skip-image-scan"
	pathFlag            = "path"
	operatorVersionFlag = "operator-version"
)

var debug bool

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
	runner := registry.MustDockerRunner()

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
		Subcommands: hashreleaseSubCommands(cfg, runner),
	})

	// The release command suite is used to build and publish official Calico releases.
	app.Commands = append(app.Commands, &cli.Command{
		Name:        "release",
		Aliases:     []string{"rel"},
		Usage:       "Build and publish official Calico releases.",
		Subcommands: releaseSubCommands(cfg),
	})

	// Run the app.
	if err := app.Run(os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running task")
	}
}

func hashreleaseSubCommands(cfg *config.Config, runner *registry.DockerRunner) []*cli.Command {
	return []*cli.Command{
		// The build command is used to produce a new local hashrelease in the output directory.
		{
			Name:  "build",
			Usage: "Build a hashrelease locally in _output/",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-build.log")
				if !c.Bool(skipValidationFlag) {
					tasks.PreReleaseValidate(cfg)
				}

				// Create the pinned-version.yaml file and extract the versions.
				ver, operatorVer := tasks.PinnedVersion(cfg)

				// Build the operator.
				tasks.OperatorHashreleaseBuild(runner, cfg)

				// Configure a release builder using the generated versions, and use it
				// to build a Calico release.
				opts := []builder.Option{
					builder.WithRepoRoot(cfg.RepoRootDir),
					builder.IsHashRelease(),
					builder.WithVersions(ver, operatorVer),
				}
				if c.Bool(skipValidationFlag) {
					opts = append(opts, builder.WithPreReleaseValidation(false))
				}
				r := builder.NewReleaseBuilder(opts...)
				if err := r.Build(); err != nil {
					return err
				}

				// For real releases, release notes are generated prior to building the release. For hash releases,
				// generate a set of release notes and add them to the hashrelease directory.
				tasks.ReleaseNotes(cfg, filepath.Join(cfg.RepoRootDir, "release", "_output", "hashrelease"))
				return nil
			},
		},

		// The publish command is used to publish a locally built hashrelease to the hashrelease server.
		{
			Name:  "publish",
			Usage: "Publish hashrelease from _output/ to hashrelease server",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.BoolFlag{Name: skipImageScanFlag, Usage: "Skip sending images to image scan service.\nIf pre-build validation is skipped, image scanning also gets skipped", Value: false},
				&cli.PathFlag{Name: pathFlag, Usage: "Path to the hashrelease to publish", Required: true},
			},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-publish.log")

				// Push the operator hashrelease first before validaion
				// This is because validation checks all images exists and sends to Image Scan Service
				tasks.OperatorHashreleasePush(runner, cfg)
				if !c.Bool(skipValidationFlag) {
					tasks.HashreleaseValidate(cfg, c.Bool(skipImageScanFlag))
				}
				tasks.HashreleasePush(cfg, c.String(pathFlag))
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
	return []*cli.Command{
		// Build release notes prior to a release.
		{
			Name:  "generate-release-notes",
			Usage: "Generate release notes for the next release",
			Action: func(c *cli.Context) error {
				configureLogging("release-notes.log")
				tasks.ReleaseNotes(cfg, filepath.Join(cfg.RepoRootDir, "release-notes"))
				return nil
			},
		},

		// Build a release.
		{
			Name:  "build",
			Usage: "Build an official Calico release",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.StringFlag{Name: operatorVersionFlag, Usage: "The version of the operator to use", Required: true},
			},
			Action: func(c *cli.Context) error {
				configureLogging("release-build.log")

				// Determine the versions to use for the release.
				ver, err := determineReleaseVersion()
				if err != nil {
					return err
				}
				operatorVer := c.String(operatorVersionFlag)

				// Configure the builder based on CLI flags.
				opts := []builder.Option{
					builder.WithRepoRoot(cfg.RepoRootDir),
					builder.WithVersions(ver, operatorVer),
				}
				if c.Bool(skipValidationFlag) {
					opts = append(opts, builder.WithPreReleaseValidation(false))
				}
				r := builder.NewReleaseBuilder(opts...)
				return r.Build()
			},
		},

		// Publish a release.
		{
			Name:  "publish",
			Usage: "Publish a pre-built Calico release",
			Action: func(c *cli.Context) error {
				configureLogging("release-publish.log")
				r := builder.NewReleaseBuilder(builder.WithRepoRoot(cfg.RepoRootDir))
				return r.PublishRelease()
			},
		},
	}
}

// determineReleaseVersion uses historical clues to figure out the next semver
// release number to use for this release.
func determineReleaseVersion() (string, error) {
	previousTag, err := command.GitVersion(".", true)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to determine latest git version")
	}
	logrus.WithField("out", previousTag).Info("Current git describe")

	// There are two types of tag that this might be - either it was a previous patch release,
	// or it was a "vX.Y.Z-0.dev" tag produced when cutting the release branch.
	if strings.Contains(previousTag, "-0.dev") {
		// This is the first release from this branch - we can simply extract the version from
		// the dev tag.
		return strings.Split(previousTag, "-0.dev")[0], nil
	} else {
		// This is a patch release - we need to parse the previous, and
		// bump the patch version.
		previousVersion := strings.Split(previousTag, "-")[0]
		logrus.WithField("previousVersion", previousVersion).Info("Previous version")
		v, err := semver.NewVersion(strings.TrimPrefix(previousVersion, "v"))
		if err != nil {
			logrus.WithField("previousVersion", previousVersion).WithError(err).Error("Failed to parse git version as semver")
			return "", fmt.Errorf("failed to parse git version as semver: %s", err)
		}
		v.BumpPatch()
		return fmt.Sprintf("v%s", v.String()), nil
	}
}
