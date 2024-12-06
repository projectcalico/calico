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
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

// The release command suite is used to build and publish official Calico releases.
func releaseCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:        "release",
		Aliases:     []string{"rel"},
		Usage:       "Build and publish official Calico releases.",
		Subcommands: releaseSubCommands(cfg),
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
				&cli.BoolFlag{Name: buildImagesFlag, Usage: "Build images from local codebase. If false, will use images from CI instead.", EnvVars: []string{"BUILD_CONTAINER_IMAGES"}, Value: true},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.StringSliceFlag{Name: imageRegistryFlag, Usage: "Specify image registry or registries to use", EnvVars: []string{"REGISTRIES"}, Value: &cli.StringSlice{}},
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
