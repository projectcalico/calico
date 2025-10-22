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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

func releaseOutputDir(repoRootDir, version string) string {
	baseOutputDir := filepath.Join(append([]string{repoRootDir}, releaseOutputPath...)...)
	return filepath.Join(baseOutputDir, "upload", version)
}

// The release command suite is used to build and publish official releases.
func releaseCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:     "release",
		Aliases:  []string{"rel"},
		Usage:    "Build and publish official releases.",
		Commands: releaseSubCommands(cfg),
	}
}

func releaseSubCommands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		// Build release notes prior to a release.
		{
			Name:  "generate-release-notes",
			Usage: "Generate release notes for the next release",
			Flags: []cli.Flag{orgFlag, devTagSuffixFlag, githubTokenFlag},
			Action: func(_ context.Context, c *cli.Command) error {
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
			Usage: "Build an official release",
			Flags: releaseBuildFlags(),
			Action: func(_ context.Context, c *cli.Command) error {
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
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithArchitectures(c.StringSlice(archFlag.Name)),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithBuildImages(c.Bool(buildImagesFlag.Name)),
					calico.WithArchiveImages(c.Bool(archiveImagesFlag.Name)),
				}
				if c.Bool(skipValidationFlag.Name) {
					opts = append(opts, calico.WithValidate(false))
					opts = append(opts, calico.WithReleaseBranchValidation(false))
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
			Usage: "Publish a pre-built release",
			Flags: releasePublishFlags(),
			Action: func(_ context.Context, c *cli.Command) error {
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
					calico.WithTmpDir(cfg.TmpDir),
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

		// Publish a release to the public.
		releasePublicSubCommands(cfg),

		// Post-release validation.
		releaseValidationSubCommand(cfg),
	}
}

func releasePublicSubCommands(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "public",
		Usage: "Make a published release available to the public",
		Flags: []cli.Flag{
			orgFlag,
			repoFlag,
			repoRemoteFlag,
			operatorOrgFlag,
			operatorRepoFlag,
			operatorRepoRemoteFlag,
		},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("release-public.log")
			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}
			opts := []calico.Option{
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithVersion(ver.FormattedString()),
				calico.WithOperatorVersion(operatorVer.FormattedString()),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(repoRemoteFlag.Name),
			}
			m := calico.NewManager(opts...)
			if err := m.ReleasePublic(); err != nil {
				return err
			}
			opOpts := []operator.Option{
				operator.WithVersion(operatorVer.FormattedString()),
				operator.WithCalicoDirectory(cfg.RepoRootDir),
				operator.WithGithubOrg(c.String(operatorOrgFlag.Name)),
				operator.WithRepoName(c.String(operatorRepoFlag.Name)),
				operator.WithRepoRemote(c.String(operatorRepoRemoteFlag.Name)),
			}
			o := operator.NewManager(opOpts...)
			return o.ReleasePublic()
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

func releaseValidationSubCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "validate",
		Usage: "Post-release validation",
		Flags: []cli.Flag{
			orgFlag,
			repoFlag,
			repoRemoteFlag,
			releaseBranchPrefixFlag,
			githubTokenFlag,
		},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("postrelease-validation.log")

			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			pinnedCfg := pinnedversion.CalicoReleaseVersions{
				Dir:                 cfg.TmpDir,
				ProductVersion:      ver.FormattedString(),
				ReleaseBranchPrefix: c.String(releaseBranchPrefixFlag.Name),
				OperatorVersion:     operatorVer.FormattedString(),
				OperatorCfg: pinnedversion.OperatorConfig{
					Image:    operator.DefaultImage,
					Registry: operator.DefaultRegistry,
				},
			}
			if _, err := pinnedCfg.GenerateFile(); err != nil {
				return fmt.Errorf("failed to generate pinned version file: %w", err)
			}
			images, err := pinnedCfg.ImageList()
			if err != nil {
				return fmt.Errorf("failed to get image list: %w", err)
			}
			flannelVer, err := pinnedCfg.FlannelVersion()
			if err != nil {
				return fmt.Errorf("failed to get flannel version: %w", err)
			}

			postreleaseDir := filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "pkg", "postrelease")
			args := []string{
				"--format=testname",
				"--", "-v", "./...",
				fmt.Sprintf("-release-version=%s", ver.FormattedString()),
				fmt.Sprintf("-operator-version=%s", operatorVer.FormattedString()),
				fmt.Sprintf("-flannel-version=%s", flannelVer),
				fmt.Sprintf("-github-org=%s", c.String(orgFlag.Name)),
				fmt.Sprintf("-github-repo=%s", c.String(repoFlag.Name)),
				fmt.Sprintf("-github-repo-remote=%s", c.String(repoRemoteFlag.Name)),
				fmt.Sprintf("-images=%s", strings.Join(images, " ")),
			}
			if c.String(githubTokenFlag.Name) != "" {
				args = append(args, fmt.Sprintf("-github-token=%s", c.String(githubTokenFlag.Name)))
			}

			cmd := exec.Command(filepath.Join(cfg.RepoRootDir, "bin", "gotestsum"), args...)
			cmd.Dir = postreleaseDir
			var errb strings.Builder
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				// If debug level is enabled, also write to stdout.
				cmd.Stdout = io.MultiWriter(os.Stdout, logrus.StandardLogger().Out)
				cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
			} else {
				// Otherwise, just capture the output to return.
				cmd.Stdout = io.MultiWriter(logrus.StandardLogger().Out)
				cmd.Stderr = io.MultiWriter(&errb)
			}
			logTestCmdSecure(postreleaseDir, "gotestsum", args)
			err = cmd.Run()
			if err != nil {
				err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
			}
			return err
		},
	}
}

func logTestCmdSecure(dir, name string, args []string) {
	var sb strings.Builder
	replacementStr := "********"
	i := 0
	for i < len(args) {
		arg := args[i]
		sb.WriteString(" ")

		lowerArg := strings.ToLower(arg)
		if strings.Contains(lowerArg, "token") || strings.Contains(lowerArg, "password") {
			if strings.Contains(lowerArg, "=") {
				parts := strings.Split(arg, "=")
				sb.WriteString(parts[0])
				sb.WriteString("=")
				sb.WriteString(replacementStr)
			} else if i+1 < len(args) {
				sb.WriteString(arg)
				sb.WriteString(" ")
				sb.WriteString(replacementStr)
				i++
			}
		} else {
			sb.WriteString(arg)
		}
		i++
	}
	logrus.WithFields(logrus.Fields{
		"cmd": name + sb.String(),
		"dir": dir,
	}).Info("Running tests")
}
