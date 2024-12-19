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
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

func releaseOutputDir(repoRootDir, version string) string {
	baseOutputDir := filepath.Join(append([]string{repoRootDir}, releaseOutputPath...)...)
	return filepath.Join(baseOutputDir, "upload", version)
}

// The release command suite is used to build and publish official Calico releases.
func releaseCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:        "release",
		Aliases:     []string{"rel"},
		Usage:       "Build and publish official Calico releases.",
		Subcommands: releaseSubCommands(cfg),
	}
}

func releaseSubCommands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		// Build release notes prior to a release.
		{
			Name:  "generate-release-notes",
			Usage: "Generate release notes for the next release",
			Flags: []cli.Flag{orgFlag, githubTokenFlag},
			Action: func(c *cli.Context) error {
				configureLogging("release-notes.log")

				// Determine the versions to use for the release.
				ver, err := version.DetermineReleaseVersion(version.GitVersion(), c.String(devTagSuffixFlag.Name))
				if err != nil {
					return err
				}

				// Generate the release notes.
				filePath, err := outputs.ReleaseNotes(c.String(orgFlag.Name), c.String(githubTokenFlag.Name), cfg.RepoRootDir, filepath.Join(cfg.RepoRootDir, releaseNotesDir), ver)
				if err != nil {
					return fmt.Errorf("failed to generate release notes: %w", err)
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
			Flags: releaseBuildFlags(),
			Action: func(c *cli.Context) error {
				configureLogging("release-build.log")

				// Determine the versions to use for the release.
				ver, err := version.DetermineReleaseVersion(version.GitVersion(), c.String(devTagSuffixFlag.Name))
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
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.WithVersion(ver.FormattedString()),
					calico.WithOperatorVersion(operatorVer.FormattedString()),
					calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, ver.FormattedString())),
					calico.WithArchitectures(c.StringSlice(archFlag.Name)),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithBuildImages(c.Bool(buildImagesFlag.Name)),
				}
				if c.Bool(skipValidationFlag.Name) {
					opts = append(opts, calico.WithValidate(false))
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
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
			Flags: releasePublishFlags(),
			Action: func(c *cli.Context) error {
				configureLogging("release-publish.log")

				ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
				if err != nil {
					return err
				}
				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithVersion(ver.FormattedString()),
					calico.WithOperatorVersion(operatorVer.FormattedString()),
					calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, ver.FormattedString())),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithPublishImages(c.Bool(publishImagesFlag.Name)),
					calico.WithPublishGitTag(c.Bool(publishGitTagFlag.Name)),
					calico.WithPublishGithubRelease(c.Bool(publishGitHubReleaseFlag.Name)),
					calico.WithGithubToken(c.String(githubTokenFlag.Name)),
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				r := calico.NewManager(opts...)
				return r.PublishRelease()
			},
		},
	}
}

// releaseBuildFlags returns the flags for release build command.
func releaseBuildFlags() []cli.Flag {
	f := append(productFlags,
		archFlag,
		registryFlag,
		buildImagesFlag,
		githubTokenFlag,
		skipValidationFlag)
	return f
}

// releasePublishFlags returns the flags for release publish command.
func releasePublishFlags() []cli.Flag {
	f := append(productFlags,
		registryFlag,
		publishImagesFlag,
		publishGitTagFlag,
		publishGitHubReleaseFlag,
		githubTokenFlag,
		skipValidationFlag)
	return f
}
