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
	"errors"
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/ci"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

func baseHashreleaseOutputDir(repoRootDir string) string {
	baseOutputDir := filepath.Join(append([]string{repoRootDir}, releaseOutputPath...)...)
	return filepath.Join(baseOutputDir, "hashrelease")
}

// hashreleaseCommand is used to build and publish hashreleases,
// as well as to interact with the hashrelease server.
func hashreleaseCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:     "hashrelease",
		Aliases:  []string{"hr"},
		Usage:    "Build and publish hashreleases.",
		Flags:    hashreleaseServerFlags,
		Commands: hashreleaseSubCommands(cfg),
	}
}

func hashreleaseSubCommands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		// The build command is used to produce a new local hashrelease in the output directory.
		{
			Name:  "build",
			Usage: "Build a hashrelease locally",
			Flags: hashreleaseBuildFlags(),
			Action: func(_ context.Context, c *cli.Command) error {
				configureLogging("hashrelease-build.log")

				// Validate flags.
				if err := validateHashreleaseBuildFlags(c); err != nil {
					return err
				}

				if err := validateCIBuildRequirements(c, cfg.RepoRootDir); err != nil {
					return err
				}

				// Clone the operator repository.
				operatorDir := filepath.Join(cfg.TmpDir, operator.DefaultRepoName)
				err := operator.Clone(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name), operatorDir)
				if err != nil {
					return fmt.Errorf("failed to clone operator repository: %v", err)
				}

				// Create the pinned config.
				pinned := pinnedversion.CalicoPinnedVersions{
					Dir:                 cfg.TmpDir,
					RootDir:             cfg.RepoRootDir,
					ReleaseBranchPrefix: c.String(releaseBranchPrefixFlag.Name),
					OperatorCfg: pinnedversion.OperatorConfig{
						Image:    c.String(operatorImageFlag.Name),
						Registry: c.String(operatorRegistryFlag.Name),
						Branch:   c.String(operatorBranchFlag.Name),
						Dir:      operatorDir,
					},
				}
				data, err := pinned.GenerateFile()
				if err != nil {
					return fmt.Errorf("failed to generate pinned version file: %v", err)
				}

				// Check if the hashrelease has already been published.
				serverCfg := hashreleaseServerConfig(c)
				if published, err := tasks.HashreleasePublished(serverCfg, data.Hash(), c.Bool(ciFlag.Name)); err != nil {
					return fmt.Errorf("failed to check if hashrelease has been published: %v", err)
				} else if published {
					// On CI, if the hashrelease has already been published, we exit successfully (return nil).
					// However, on local builds, we just log a warning and continue.
					if c.Bool(ciFlag.Name) {
						logrus.Infof("hashrelease %s has already been published", data.Hash())
						return nil
					} else {
						logrus.Warnf("hashrelease %s has already been published", data.Hash())
					}
				}

				productRegistriesFromFlag := c.StringSlice(registryFlag.Name)

				// Build the operator
				operatorOpts := []operator.Option{
					operator.WithOperatorDirectory(operatorDir),
					operator.WithReleaseBranchPrefix(c.String(operatorReleaseBranchPrefixFlag.Name)),
					operator.IsHashRelease(),
					operator.WithImage(c.String(operatorImageFlag.Name)),
					operator.WithArchitectures(c.StringSlice(archFlag.Name)),
					operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
					operator.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
					operator.WithVersion(data.OperatorVersion()),
					operator.WithCalicoDirectory(cfg.RepoRootDir),
					operator.WithTempDirectory(cfg.TmpDir),
				}
				if reg := c.String(operatorRegistryFlag.Name); reg != "" {
					operatorOpts = append(operatorOpts, operator.WithRegistry(reg))
				}
				if len(productRegistriesFromFlag) > 0 {
					operatorOpts = append(operatorOpts, operator.WithProductRegistry(productRegistriesFromFlag[0]))
				}
				if !c.Bool(skipOperatorFlag.Name) {
					o := operator.NewManager(operatorOpts...)
					if err := o.Build(); err != nil {
						return err
					}
				}

				// Extract the pinned version as a hashrelease.
				hashrel, err := pinnedversion.LoadHashrelease(cfg.RepoRootDir, cfg.TmpDir, baseHashreleaseOutputDir(cfg.RepoRootDir), false)
				if err != nil {
					return fmt.Errorf("load hashrelease from pinned file: %v", err)
				}

				opts := []calico.Option{
					calico.WithVersion(data.ProductVersion()),
					calico.WithOperator(c.String(operatorRegistryFlag.Name), c.String(operatorImageFlag.Name), data.OperatorVersion()),
					calico.WithOperatorGit(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name)),
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.IsHashRelease(),
					calico.WithHashrelease(*hashrel, *serverCfg),
					calico.WithOutputDir(hashrel.Source),
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithBuildImages(c.Bool(buildHashreleaseImagesFlag.Name)),
					calico.WithArchiveImages(c.Bool(archiveHashreleaseImagesFlag.Name)),
					calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
					calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithArchitectures(c.StringSlice(archFlag.Name)),
				}
				if len(productRegistriesFromFlag) > 0 {
					opts = append(opts, calico.WithImageRegistries(productRegistriesFromFlag))
				}
				r := calico.NewManager(opts...)
				if err := r.Build(); err != nil {
					return err
				}

				// For real releases, release notes are generated prior to building the release.
				// For hash releases, generate a set of release notes and add them to the hashrelease directory.
				releaseVersion, err := version.DetermineReleaseVersion(version.New(data.ProductVersion()), c.String(devTagSuffixFlag.Name))
				if err != nil {
					return fmt.Errorf("failed to determine release version: %v", err)
				}
				if c.String(orgFlag.Name) == utils.TigeraOrg {
					logrus.Warn("Release notes are not supported for Tigera releases, skipping...")
				} else {
					if _, err := outputs.ReleaseNotes(utils.ProjectCalicoOrg, c.String(githubTokenFlag.Name), cfg.RepoRootDir, filepath.Join(hashrel.Source, releaseNotesDir), releaseVersion); err != nil {
						return err
					}
				}

				// Adjsut the formatting of the generated outputs to match the legacy hashrelease format.
				return tasks.ReformatHashrelease(hashrel.Source, cfg.TmpDir)
			},
		},

		// The publish command is used to publish a locally built hashrelease to the hashrelease server.
		{
			Name:  "publish",
			Usage: "Publish a pre-built hashrelease",
			Flags: hashreleasePublishFlags(),
			Action: func(_ context.Context, c *cli.Command) error {
				configureLogging("hashrelease-publish.log")

				// Validate flags.
				if err := validateHashreleasePublishFlags(c); err != nil {
					return err
				}

				// Extract the pinned version as a hashrelease.
				hashrel, err := pinnedversion.LoadHashrelease(cfg.RepoRootDir, cfg.TmpDir, baseHashreleaseOutputDir(cfg.RepoRootDir), c.Bool(latestFlag.Name))
				if err != nil {
					return fmt.Errorf("failed to load hashrelease from pinned file: %v", err)
				}

				// Check if the hashrelease has already been published.
				serverCfg := hashreleaseServerConfig(c)
				if published, err := tasks.HashreleasePublished(serverCfg, hashrel.Hash, c.Bool(ciFlag.Name)); err != nil {
					return fmt.Errorf("failed to check if hashrelease has been published: %v", err)
				} else if published {
					// On CI, we exit successfully (return nil) if the hashrelease has already been published.
					// This is not an error scenario; we just log a warning and continue locally.
					if c.Bool(ciFlag.Name) {
						logrus.Infof("hashrelease %s has already been published", hashrel.Hash)
						return nil
					} else {
						logrus.Warnf("hashrelease %s has already been published", hashrel.Hash)
					}
				}

				// Push the operator hashrelease first before validaion
				// This is because validation checks all images exists and sends to Image Scan Service
				o := operator.NewManager(
					operator.WithOperatorDirectory(filepath.Join(cfg.TmpDir, operator.DefaultRepoName)),
					operator.IsHashRelease(),
					operator.WithArchitectures(c.StringSlice(archFlag.Name)),
					operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
					operator.WithTempDirectory(cfg.TmpDir),
				)
				if !c.Bool(skipOperatorFlag.Name) {
					if err := o.Publish(); err != nil {
						return err
					}
				}

				opts := []calico.Option{
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.IsHashRelease(),
					calico.WithVersion(hashrel.ProductVersion),
					calico.WithOperatorVersion(hashrel.OperatorVersion),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
					calico.WithTmpDir(cfg.TmpDir),
					calico.WithOutputDir(hashrel.Source),
					calico.WithHashrelease(*hashrel, *serverCfg),
					calico.WithPublishImages(c.Bool(publishHashreleaseImagesFlag.Name)),
					calico.WithPublishCharts(c.Bool(publishChartsFlag.Name)),
					calico.WithPublishHashrelease(c.Bool(publishHashreleaseFlag.Name)),
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts,
						calico.WithImageRegistries(reg),
						calico.WithImageScanning(false, imagescanner.Config{}), // Disable image scanning if using custom registries.
					)
				} else {
					opts = append(opts, calico.WithImageScanning(!c.Bool(skipImageScanFlag.Name), *imageScanningAPIConfig(c)))
				}
				components, err := pinnedversion.RetrieveImageComponents(cfg.TmpDir)
				if err != nil {
					return fmt.Errorf("failed to retrieve images for hashrelease: %w", err)
				}
				opts = append(opts, calico.WithComponents(components))
				if reg := c.StringSlice(helmRegistryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithHelmRegistries(reg))
				}
				r := calico.NewManager(opts...)
				if err := r.PublishRelease(); err != nil {
					return err
				}

				if !c.Bool(skipImageScanFlag.Name) {
					url, err := imagescanner.RetrieveResultURL(cfg.TmpDir)
					// Only log error as a warning if the image scan result URL could not be retrieved
					// as it is not an error that should stop the hashrelease process.
					if err != nil {
						logrus.WithError(err).Warn("Failed to retrieve image scan result URL")
					} else if url == "" {
						logrus.Warn("Image scan result URL is empty")
					}
					hashrel.ImageScanResultURL = url
				}

				// Send a slack message to notify that the hashrelease has been published.
				if c.Bool(publishHashreleaseFlag.Name) && c.Bool(notifyFlag.Name) {
					if _, err := tasks.AnnounceHashrelease(slackConfig(c), hashrel, ciJobURL(c)); err != nil {
						logrus.WithError(err).Warn("Failed to send hashrelease announcement to Slack")
					}
				}
				return nil
			},
		},
	}
}

// hashreleaseBuildFlags returns the flags for the hashrelease build command.
func hashreleaseBuildFlags() []cli.Flag {
	f := append(productFlags,
		registryFlag,
		buildHashreleaseImagesFlag,
		archiveHashreleaseImagesFlag,
		archFlag)
	f = append(f, operatorBuildFlags...)
	f = append(f,
		skipOperatorFlag,
		skipBranchCheckFlag,
		skipValidationFlag,
		githubTokenFlag)
	return f
}

// validateHashreleaseBuildFlags checks that the flags are set correctly for the hashrelease build command.
func validateHashreleaseBuildFlags(c *cli.Command) error {
	// If using a custom registry for product, ensure operator is also using a custom registry.
	if len(c.StringSlice(registryFlag.Name)) > 0 && c.String(operatorRegistryFlag.Name) == "" {
		return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag, registryFlag)
	}

	if c.Bool(archiveHashreleaseImagesFlag.Name) && !c.Bool(buildHashreleaseImagesFlag.Name) {
		return fmt.Errorf("cannot archive images without building them; set --%s to 'true'", buildHashreleaseImagesFlag.Name)
	}
	if !c.Bool(archiveHashreleaseImagesFlag.Name) && c.Bool(buildHashreleaseImagesFlag.Name) {
		logrus.Warnf("Images are built but not archived; to archive images set --%s to 'true'", archiveHashreleaseImagesFlag.Name)
	}

	// CI conditional checks.
	if c.Bool(ciFlag.Name) {
		if !hashreleaseServerConfig(c).Valid() {
			return fmt.Errorf("missing hashrelease publishing configuration, ensure --%s is set",
				hashreleaseServerBucketFlag.Name)
		}
		if c.String(ciTokenFlag.Name) == "" {
			return fmt.Errorf("%s API token must be set when running on CI, either set \"SEMAPHORE_API_TOKEN\" or use %s flag", semaphoreCI, ciTokenFlag.Name)
		}
	} else {
		// If building images, log a warning if no registry is specified.
		if c.Bool(buildHashreleaseImagesFlag.Name) && len(c.StringSlice(registryFlag.Name)) == 0 {
			logrus.Warn("Building images without specifying a registry will result in images being built with the default registries")
		}

		// If using the default operator image and registry, log a warning.
		if c.String(operatorRegistryFlag.Name) == "" {
			logrus.Warnf("Local builds should specify an operator registry using %s", operatorRegistryFlag)
		}
	}

	return nil
}

// hashreleasePublishFlags returns the flags for the hashrelease publish command.
func hashreleasePublishFlags() []cli.Flag {
	f := append(gitFlags,
		registryFlag,
		helmRegistryFlag,
		publishHashreleaseImagesFlag,
		publishChartsFlag,
		archFlag,
		publishHashreleaseFlag,
		latestFlag,
		skipOperatorFlag,
		skipValidationFlag,
		skipImageScanFlag)
	f = append(f, imageScannerAPIFlags...)
	return f
}

// validateHashreleasePublishFlags checks that the flags are set correctly for the hashrelease publish command.
func validateHashreleasePublishFlags(c *cli.Command) error {
	// If publishing the hashrelease
	if c.Bool(publishHashreleaseFlag.Name) {
		//  check that hashrelease server configuration is set.
		if !hashreleaseServerConfig(c).Valid() {
			return fmt.Errorf("missing hashrelease publishing configuration, ensure --%s is set",
				hashreleaseServerBucketFlag.Name)
		}
		if c.Bool(latestFlag.Name) {
			// If using a custom registry, do not allow setting the hashrelease as latest.
			if len(c.StringSlice(registryFlag.Name)) > 0 {
				return fmt.Errorf("cannot set hashrelease as latest when using a custom registry")
			}
			// If building locally, do not allow setting the hashrelease as latest.
			if !c.Bool(ciFlag.Name) {
				return fmt.Errorf("cannot set hashrelease as latest when building locally, use --%s=false instead", latestFlag.Name)
			}
		}
	}

	// If skipValidationFlag is set, then skipImageScanFlag must also be set.
	if c.Bool(skipValidationFlag.Name) && !c.Bool(skipImageScanFlag.Name) {
		return fmt.Errorf("%s must be set if %s is set", skipImageScanFlag, skipValidationFlag)
	}
	return nil
}

// ciJobURL returns the URL to the CI job if the command is running on CI.
func ciJobURL(c *cli.Command) string {
	if !c.Bool(ciFlag.Name) {
		return ""
	}
	return fmt.Sprintf("%s/jobs/%s", c.String(ciBaseURLFlag.Name), c.String(ciJobIDFlag.Name))
}

func hashreleaseServerConfig(c *cli.Command) *hashreleaseserver.Config {
	return &hashreleaseserver.Config{
		BucketName: c.String(hashreleaseServerBucketFlag.Name),
	}
}

func imageScanningAPIConfig(c *cli.Command) *imagescanner.Config {
	return &imagescanner.Config{
		APIURL:  c.String(imageScannerAPIFlag.Name),
		Token:   c.String(imageScannerTokenFlag.Name),
		Scanner: c.String(imageScannerSelectFlag.Name),
	}
}

func validateCIBuildRequirements(c *cli.Command, repoRootDir string) error {
	if !c.Bool(ciFlag.Name) {
		return nil
	}
	if c.Bool(buildHashreleaseImagesFlag.Name) {
		logrus.Info("Building images in hashrelease, skipping images promotions check...")
		return nil
	}
	orgURL := c.String(ciBaseURLFlag.Name)
	token := c.String(ciTokenFlag.Name)
	pipelineID := c.String(ciPipelineIDFlag.Name)
	promotionsDone, err := ci.EvaluateImagePromotions(repoRootDir, orgURL, pipelineID, token)
	if err != nil {
		return err
	}
	if !promotionsDone {
		return errors.New("images promotions are not done, wait for all images promotions to pass before publishing the hashrelease")
	}
	return nil
}
