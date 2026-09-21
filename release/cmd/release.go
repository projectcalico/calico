// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/manifests"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

func releaseOutputDir(repoRootDir, version string) string {
	baseOutputDir := filepath.Join(append([]string{repoRootDir}, releaseOutputPath...)...)
	return filepath.Join(baseOutputDir, "release", version)
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

var releaseSubCommands = func(cfg *Config) []*cli.Command {
	return []*cli.Command{
		// Prepare for a release.
		releasePrepCommand(cfg),

		// Build release notes prior to a release.
		{
			Name:  "generate-release-notes",
			Usage: "Generate release notes for the next release",
			Flags: []cli.Flag{orgFlag, devTagSuffixFlag},
			Action: func(_ context.Context, c *cli.Command) error {
				configureLogging("release-notes.log")

				// Determine the versions to use for the release.
				gitVer, err := version.GitVersion()
				if err != nil {
					return err
				}
				ver, err := version.DetermineReleaseVersion(gitVer, c.String(devTagSuffixFlag.Name))
				if err != nil {
					return err
				}

				// Generate the release notes.
				filePath, err := outputs.ReleaseNotes(c.String(orgFlag.Name), cfg.RepoRootDir, "", ver)
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
				o, err := releaseOperator(cfg, c)
				if err != nil {
					return fmt.Errorf("operator: %w", err)
				}
				gitVer, err := version.GitVersion()
				if err != nil {
					return fmt.Errorf("release version: %w", err)
				}
				ver, err := version.DetermineReleaseVersion(gitVer, c.String(devTagSuffixFlag.Name))
				if err != nil {
					return fmt.Errorf("release version: %w", err)
				}
				if ver.String() != o.ProductVersion {
					return fmt.Errorf("manifests are at %s but git says this release is %s: run release prep first", o.ProductVersion, ver.String())
				}

				// Configure the builder.
				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.WithVersion(o.ProductVersion),
					calico.WithOperatorImage(operator.Registry(*o), o.Image, o.Version),
					calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, o.ProductVersion)),
					calico.WithRecordsDir(outputs.RecordsDir(cfg.OutputDir, o.ProductVersion)),
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithLogsDir(filepath.Join(cfg.LogsDir, o.ProductVersion)),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithImages(c.Bool(imagesFlagName)),
					calico.WithArchitectures(c.StringSlice(archFlag.Name)),
					calico.WithImageReleaseDirs(c.StringSlice(imageReleaseDirsFlag.Name)),
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
					calico.WithDryRun(c.Bool(localFlag.Name)),
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				// The operator carries the versions of the images it deploys in its binary, so a
				// release rebuilds it rather than retagging the one a hashrelease published.
				if c.Bool(operatorFlagName) {
					if err := operator.Build(*o, operatorVariants(c), false,
						operatorBuildOptions(c, filepath.Join(cfg.LogsDir, o.ProductVersion))...); err != nil {
						return fmt.Errorf("operator build: %w", err)
					}
				}

				r, err := calico.NewManager(opts...)
				if err != nil {
					return fmt.Errorf("calico manager: %w", err)
				}
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

				o, err := releaseOperator(cfg, c)
				if err != nil {
					return fmt.Errorf("operator: %w", err)
				}
				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.WithVersion(o.ProductVersion),
					calico.WithOperatorImage(operator.Registry(*o), o.Image, o.Version),
					calico.WithOperator(c.Bool(operatorFlagName)),
					calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, o.ProductVersion)),
					calico.WithRecordsDir(outputs.RecordsDir(cfg.OutputDir, o.ProductVersion)),
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithLogsDir(filepath.Join(cfg.LogsDir, o.ProductVersion)),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithImages(c.Bool(imagesFlagName)),
					calico.WithImageReleaseDirs(c.StringSlice(imageReleaseDirsFlag.Name)),
					calico.WithHelmCharts(c.Bool(helmChartsFlagName)),
					calico.WithHelmIndex(c.Bool(helmIndexFlagName)),
					calico.WithGitRef(c.Bool(gitRefFlag.Name)),
					calico.WithGithubRelease(c.Bool(githubReleaseFlag.Name)),
					calico.WithDraftRelease(c.Bool(draftGithubReleaseFlag.Name)),
					calico.WithValidation(c.Bool(validationFlag.Name)),
					calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
					calico.WithDryRun(c.Bool(localFlag.Name)),
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				pin, err := pinForRelease(cfg, c)
				if err != nil {
					return err
				}
				opts = append(opts, calico.WithComponents(pin.Released()))
				if reg := c.StringSlice(helmRegistryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithHelmRegistries(reg))
				}
				if v := c.String(awsProfileFlag.Name); v != "" {
					opts = append(opts, calico.WithAWSProfile(v))
				}
				if v := c.String(s3BucketFlag.Name); v != "" {
					opts = append(opts, calico.WithS3Bucket(v))
				}
				if c.Bool(operatorFlagName) {
					oOpts, err := operatorPublishOptions(c, outputs.RecordsDir(cfg.OutputDir, o.ProductVersion), filepath.Join(cfg.LogsDir, o.ProductVersion))
					if err != nil {
						return fmt.Errorf("operator publish options: %w", err)
					}
					if err := operator.Publish(*o, operatorVariants(c), false, oOpts...); err != nil {
						return fmt.Errorf("operator publish: %w", err)
					}
				}

				r, err := calico.NewManager(opts...)
				if err != nil {
					return fmt.Errorf("calico manager: %w", err)
				}
				return r.PublishRelease()
			},
		},

		// Post-release validation.
		releaseValidationSubCommand(cfg),
	}
}

func releasePrepCommand(cfg *Config) *cli.Command {
	flags := slices.Clone(productFlags)
	flags = append(flags,
		branchCheckFlag,
		validationFlag,
		localFlag,
	)
	return &cli.Command{
		Name:  "prep",
		Usage: "Prepare for a Calico release",
		Flags: flags,
		Action: withLogging(withSummary(cfg, "release-prep", func(_ context.Context, c *cli.Command) (string, map[string]any, error) {
			// Determine the versions to use for the release.
			gitVer, err := version.GitVersion()
			if err != nil {
				return "", nil, err
			}
			ver, err := version.DetermineReleaseVersion(gitVer, c.String(devTagSuffixFlag.Name))
			if err != nil {
				return "", nil, err
			}
			outs := map[string]any{
				"version": ver.String(),
			}
			operatorVer := ver.String()
			outs["operator"] = operatorVer

			// Generate release notes
			if _, err := outputs.ReleaseNotes(c.String(orgFlag.Name), cfg.RepoRootDir, "", ver); err != nil {
				return ver.String(), outs, fmt.Errorf("generate release notes: %w", err)
			}

			// Prepare the release using the manager.
			opts := []calico.Option{
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.WithVersion(ver.String()),
				calico.WithOperatorVersion(operatorVer),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithTmpDir(cfg.TmpDir),
				calico.WithValidation(c.Bool(validationFlag.Name)),
				calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
				calico.WithDryRun(c.Bool(localFlag.Name)),
			}
			r, err := calico.NewManager(opts...)
			if err != nil {
				return ver.String(), outs, fmt.Errorf("calico manager: %w", err)
			}
			branch, err := r.PrepareRelease()
			if err != nil {
				return ver.String(), outs, fmt.Errorf("prepare release: %w", err)
			}
			outs["branch"] = branch
			return ver.String(), outs, nil
		})),
	}
}

// releaseBuildFlags returns the flags for release build command.
func releaseBuildFlags() []cli.Flag {
	f := append(slices.Clone(productFlags), buildStepFlags(false)...)
	f = append(f,
		registryFlag,
		archFlag,
		imageReleaseDirsFlag)
	f = append(f, operatorBuildCommandFlags...)
	f = append(f,
		branchCheckFlag,
		validationFlag,
		localFlag)
	return f
}

// releasePublishFlags returns the flags for release publish command.
func releasePublishFlags() []cli.Flag {
	f := append(slices.Clone(productFlags), publishStepFlags(false)...)
	f = append(f, operatorPublishCommandFlags...)
	f = append(f,
		registryFlag,
		imageReleaseDirsFlag,
		helmRegistryFlag,
		awsProfileFlag,
		s3BucketFlag,
		branchCheckFlag,
		validationFlag,
		localFlag,
	)
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
		},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("postrelease-validation.log")

			ver, operatorVer, err := manifests.Versions(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			imgs, err := images.ReleaseImages()
			if err != nil {
				return err
			}

			postreleaseDir := filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "pkg", "postrelease")
			args := []string{
				"--format=testname",
				"--", "-v", "./...",
				fmt.Sprintf("-release-version=%s", ver.String()),
				fmt.Sprintf("-operator-version=%s", operatorVer.String()),
				fmt.Sprintf("-flannel-version=%s", pinnedversion.FlannelComponent.Version),
				fmt.Sprintf("-github-org=%s", c.String(orgFlag.Name)),
				fmt.Sprintf("-github-repo=%s", c.String(repoFlag.Name)),
				fmt.Sprintf("-github-repo-remote=%s", c.String(repoRemoteFlag.Name)),
				fmt.Sprintf("-images=%s", strings.Join(imgs, " ")),
			}

			// gotestsum is a `tool` directive in the repo's root go.mod, so it
			// is run through the Go toolchain rather than from a bin/ copy.
			// cmd.Dir is inside that module, which is what lets `go tool`
			// resolve it and what keeps "./..." scoped to the test package.
			cmd := exec.Command("go", append([]string{"tool", "gotestsum"}, args...)...)
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
