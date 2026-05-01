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
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/command"
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
		// Prepare for a release.
		releasePrepCommand(cfg),

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
				filePath, err := outputs.ReleaseNotes(c.String(orgFlag.Name), c.String(githubTokenFlag.Name), cfg.RepoRootDir, "", ver)
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
					calico.WithOperatorGit(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name)),
					calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, ver.FormattedString())),
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithImages(c.Bool(imagesFlagName)),
					calico.WithArchitectures(c.StringSlice(archFlag.Name)),
					calico.WithArchiveImages(c.Bool(archiveImagesFlagName)),
					calico.WithHelmCharts(c.Bool(helmChartsFlagName)),
					calico.WithManifests(c.Bool(manifestsFlag.Name)),
					calico.WithBinaries(c.Bool(binariesFlag.Name)),
					calico.WithOCPBundle(c.Bool(ocpBundleFlag.Name)),
					calico.WithTarball(c.Bool(tarballFlag.Name)),
					calico.WithWindowsArchive(c.Bool(windowsArchiveFlagName)),
					calico.WithHelmIndex(c.Bool(helmIndexFlagName)),
					calico.WithValidation(c.Bool(validationFlag.Name)),
					calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
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
					calico.WithOperatorBranch(c.String(operatorBranchFlag.Name)),
					calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, ver.FormattedString())),
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithGithubToken(c.String(githubTokenFlag.Name)),
					calico.WithImages(c.Bool(imagesFlagName)),
					calico.WithHelmCharts(c.Bool(helmChartsFlagName)),
					calico.WithHelmIndex(c.Bool(helmIndexFlagName)),
					calico.WithGitRef(c.Bool(gitRefFlag.Name)),
					calico.WithGithubRelease(c.Bool(githubReleaseFlag.Name)),
					calico.WithValidation(c.Bool(validationFlag.Name)),
					calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				if reg := c.StringSlice(helmRegistryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithHelmRegistries(reg))
				}
				if v := c.String(awsProfileFlag.Name); v != "" {
					opts = append(opts, calico.WithAWSProfile(v))
				}
				if v := c.String(s3BucketFlag.Name); v != "" {
					opts = append(opts, calico.WithS3Bucket(v))
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
				calico.WithOperatorGit(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name)),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
			}
			m := calico.NewManager(opts...)
			if err := m.ReleasePublic(); err != nil {
				return err
			}
			opOpts := []operator.Option{
				operator.WithVersion(operatorVer.FormattedString()),
				operator.WithCalicoDirectory(cfg.RepoRootDir),
			}
			o := operator.NewManager(opOpts...)
			return o.ReleasePublic()
		},
	}
}

func determineOperatorReleaseVersion(c *cli.Command, tmpDir string) (string, error) {
	// Clone the operator repository to determine the operator version.
	operatorDir := filepath.Join(tmpDir, operator.Repo())
	if err := operator.Clone(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name), operatorDir); err != nil {
		return "", fmt.Errorf("clone operator repository: %w", err)
	}
	defer func() { _ = os.RemoveAll(operatorDir) }()
	operatorGitVer, err := command.GitVersion(operatorDir, true)
	if err != nil {
		return "", fmt.Errorf("determine operator git version: %w", err)
	}
	operatorVer, err := version.DetermineReleaseVersion(version.New(operatorGitVer), operator.DefaultDevTagSuffix)
	if err != nil {
		return "", err
	}
	return operatorVer.FormattedString(), nil
}

func releasePrepCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "prep",
		Usage: "Prepare for a Calico release",
		Flags: []cli.Flag{
			orgFlag,
			repoFlag,
			repoRemoteFlag,
			releaseBranchPrefixFlag,
			devTagSuffixFlag,
			operatorOrgFlag,
			operatorRepoFlag,
			operatorBranchFlag,
			githubTokenFlag,
			branchCheckFlag,
			validationFlag,
			localFlag,
		},
		Action: withLogging(withSummary(cfg, "release-prep", func(_ context.Context, c *cli.Command) (string, map[string]any, error) {
			// Determine the versions to use for the release.
			ver, err := version.DetermineReleaseVersion(version.GitVersion(), c.String(devTagSuffixFlag.Name))
			if err != nil {
				return "", nil, err
			}
			outs := map[string]any{
				"version": ver.FormattedString(),
			}
			operatorVer, err := determineOperatorReleaseVersion(c, cfg.TmpDir)
			if err != nil {
				return "", outs, err
			}
			outs["operator"] = operatorVer

			// Generate release notes
			if _, err := outputs.ReleaseNotes(c.String(orgFlag.Name), c.String(githubTokenFlag.Name), cfg.RepoRootDir, "", ver); err != nil {
				return ver.FormattedString(), outs, fmt.Errorf("generate release notes: %w", err)
			}

			// Prepare the release using the manager.
			opts := []calico.Option{
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.WithVersion(ver.FormattedString()),
				calico.WithOperatorVersion(operatorVer),
				calico.WithOperatorGit(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name)),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithTmpDir(cfg.TmpDir),
				calico.WithValidation(c.Bool(validationFlag.Name)),
				calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
				calico.WithGitRef(!c.Bool(localFlag.Name)),
			}
			r := calico.NewManager(opts...)
			branch, err := r.PrepareRelease()
			if err != nil {
				return ver.FormattedString(), outs, err
			}
			outs["branch"] = branch
			return ver.FormattedString(), outs, nil
		})),
	}
}

// releaseBuildFlags returns the flags for release build command.
func releaseBuildFlags() []cli.Flag {
	f := append(slices.Clone(productFlags), buildStepFlags(false)...)
	f = append(f,
		registryFlag,
		archFlag)
	f = append(f, operatorGitFlags...)
	f = append(f,
		branchCheckFlag,
		validationFlag,
		githubTokenFlag)
	return f
}

// releasePublishFlags returns the flags for release publish command.
func releasePublishFlags() []cli.Flag {
	f := append(slices.Clone(productFlags), publishStepFlags(false)...)
	f = append(f,
		registryFlag,
		helmRegistryFlag,
		githubTokenFlag,
		awsProfileFlag,
		s3BucketFlag,
		branchCheckFlag,
		validationFlag,
	)
	f = append(f, operatorGitFlags...)
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

			postreleaseDir := filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "pkg", "postrelease")
			args := []string{
				"--format=testname",
				"--", "-v", "./...",
				fmt.Sprintf("-release-version=%s", ver.FormattedString()),
				fmt.Sprintf("-operator-version=%s", operatorVer.FormattedString()),
				fmt.Sprintf("-flannel-version=%s", pinnedversion.FlannelComponent.Version),
				fmt.Sprintf("-github-org=%s", c.String(orgFlag.Name)),
				fmt.Sprintf("-github-repo=%s", c.String(repoFlag.Name)),
				fmt.Sprintf("-github-repo-remote=%s", c.String(repoRemoteFlag.Name)),
				fmt.Sprintf("-images=%s", strings.Join(utils.ReleaseImages(), " ")),
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
