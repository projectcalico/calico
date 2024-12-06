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

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

// hashreleaseDir is the directory where hashreleases are built relative to the repo root.
var hashreleaseDir = []string{"release", "_output", "hashrelease"}

// The hashrelease command suite is used to build and publish hashreleases,
// as well as to interact with the hashrelease server.
func hashreleaseCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:        "hashrelease",
		Aliases:     []string{"hr"},
		Usage:       "Build and publish hashreleases.",
		Subcommands: hashreleaseSubCommands(cfg),
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
				&cli.BoolFlag{Name: buildImagesFlag, Usage: "Build images from local codebase. If false, will use images from CI instead.", EnvVars: []string{"BUILD_CONTAINER_IMAGES"}, Value: false},
				&cli.StringSliceFlag{Name: imageRegistryFlag, Usage: "Specify image registry or registries to use", EnvVars: []string{"REGISTRIES"}, Value: &cli.StringSlice{}},
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
				if len(c.StringSlice(imageRegistryFlag)) > 0 && c.String(operatorRegistryFlag) == "" {
					return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag, imageRegistryFlag)
				}
				if c.String(operatorImageFlag) != "" && c.String(operatorRegistryFlag) == "" {
					return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag, operatorImageFlag)
				} else if c.String(operatorRegistryFlag) != "" && c.String(operatorImageFlag) == "" {
					return fmt.Errorf("%s must be set if %s is set", operatorImageFlag, operatorRegistryFlag)
				}
				if !cfg.CI.IsCI {
					if len(c.StringSlice(imageRegistryFlag)) == 0 && c.Bool(buildImagesFlag) {
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
					operator.WithCalicoDirectory(cfg.RepoRootDir),
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
				if reg := c.StringSlice(imageRegistryFlag); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}

				r := calico.NewManager(opts...)
				if err := r.Build(); err != nil {
					return err
				}

				// For real releases, release notes are generated prior to building the release.
				// For hash releases, generate a set of release notes and add them to the hashrelease directory.
				releaseVersion, err := version.DetermineReleaseVersion(versions.ProductVersion, cfg.DevTagSuffix)
				if err != nil {
					return fmt.Errorf("failed to determine release version: %v", err)
				}
				if _, err := outputs.ReleaseNotes(config.DefaultOrg, cfg.GithubToken, cfg.RepoRootDir, filepath.Join(dir, releaseNotesDir), releaseVersion); err != nil {
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
				&cli.StringFlag{Name: orgFlag, Usage: "Git organization", EnvVars: []string{"ORGANIZATION"}, Value: config.DefaultOrg},
				&cli.StringFlag{Name: repoFlag, Usage: "Git repository", EnvVars: []string{"GIT_REPO"}, Value: config.DefaultRepo},
				&cli.StringSliceFlag{Name: imageRegistryFlag, Usage: "Specify image registry or registries to use", EnvVars: []string{"REGISTRIES"}, Value: &cli.StringSlice{}},
				&cli.BoolFlag{Name: skipPublishImagesFlag, Usage: "Skip publishing of container images to registry/registries", EnvVars: []string{"SKIP_PUBLISH_IMAGES"}, Value: true},
				&cli.BoolFlag{Name: skipPublishHashreleaseFlag, Usage: "Skip publishing to hashrelease server", Value: false},
				&cli.BoolFlag{Name: latestFlag, Usage: "Promote this release as the latest for this stream", Value: true},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
				&cli.BoolFlag{Name: skipImageScanFlag, Usage: "Skip sending images to image scan service.", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-publish.log")

				// If using a custom registry, do not set the hashrelease as latest
				if len(c.StringSlice(imageRegistryFlag)) > 0 && c.Bool(latestFlag) {
					return fmt.Errorf("cannot set hashrelease as latest when using a custom registry")
				}

				// If skipValidationFlag is set, then we will also skip the image scan. Ensure the user
				// has set the correct flags.
				if c.Bool(skipValidationFlag) && !c.Bool(skipImageScanFlag) {
					return fmt.Errorf("%s must be set if %s is set", skipImageScanFlag, skipValidationFlag)
				}

				// Extract the pinned version as a hashrelease.
				hashrel, err := pinnedversion.LoadHashrelease(cfg.RepoRootDir, cfg.TmpFolderPath(), dir)
				if err != nil {
					return err
				}
				if c.Bool(latestFlag) {
					hashrel.Latest = true
				}

				// Check if the hashrelease has already been published.
				if published, err := tasks.HashreleasePublished(cfg, hashrel.Hash); err != nil {
					return err
				} else if published {
					return fmt.Errorf("%s hashrelease (%s) has already been published", hashrel.Name, hashrel.Hash)
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

				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.IsHashRelease(),
					calico.WithVersions(&version.Data{
						ProductVersion:  version.New(hashrel.ProductVersion),
						OperatorVersion: version.New(hashrel.OperatorVersion),
					}),
					calico.WithGithubOrg(c.String(orgFlag)),
					calico.WithRepoName(c.String(repoFlag)),
					calico.WithRepoRemote(cfg.GitRemote),
					calico.WithValidate(!c.Bool(skipValidationFlag)),
					calico.WithTmpDir(cfg.TmpFolderPath()),
					calico.WithHashrelease(*hashrel, cfg.HashreleaseServerConfig),
					calico.WithPublishImages(!c.Bool(skipPublishImagesFlag)),
					calico.WithPublishHashrelease(!c.Bool(skipPublishHashreleaseFlag)),
					calico.WithImageScanning(!c.Bool(skipImageScanFlag), cfg.ImageScannerConfig),
				}
				if reg := c.StringSlice(imageRegistryFlag); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				r := calico.NewManager(opts...)
				if err := r.PublishRelease(); err != nil {
					return err
				}

				// Send a slack message to notify that the hashrelease has been published.
				if !c.Bool(skipPublishHashreleaseFlag) {
					if err := tasks.HashreleaseSlackMessage(cfg, hashrel); err != nil {
						return err
					}
				}
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
				return hashreleaseserver.CleanOldHashreleases(&cfg.HashreleaseServerConfig)
			},
		},
	}
}
