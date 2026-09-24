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
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/ci"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

// parts for generating the pinned version
var (
	productRegistry = func(c *cli.Command) string {
		reg := c.StringSlice(registryFlag.Name)
		if len(reg) == 0 {
			return registry.DefaultProductRegistry
		}
		return reg[0]
	}
	pinConfig = func(cfg *Config, c *cli.Command) pinnedversion.Config {
		return pinnedversion.Config{
			Dir:                 cfg.TmpDir,
			RootDir:             cfg.RepoRootDir,
			ReleaseBranchPrefix: c.String(releaseBranchPrefixFlag.Name),
			Registry:            productRegistry(c),
			Operator: registry.Component{
				Image:    registry.OperatorImage,
				Registry: operatorRegistries(c)[0],
			},
		}
	}

	localPinLoader = func(cfg pinnedversion.Config) pinnedversion.LocalLoader {
		return pinnedversion.LocalLoader{Config: cfg}
	}
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

// hashreleaseSubCommands is a var so a product can supply its own set.
var hashreleaseSubCommands = func(cfg *Config) []*cli.Command {
	return []*cli.Command{
		hashreleaseBuildCommand(cfg),
		hashreleasePublishCommand(cfg),
	}
}

// The build command is used to produce a new local hashrelease in the output directory.
var hashreleaseBuildCommand = func(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "build",
		Usage:  "Build a hashrelease",
		Flags:  hashreleaseBuildFlags(),
		Action: hashreleaseBuildAction(cfg),
	}
}

var hashreleaseBuildAction = func(cfg *Config) func(_ context.Context, c *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("hashrelease-build.log")

		// Validate flags.
		if err := validateHashreleaseBuildFlags(c); err != nil {
			return err
		}

		if err := validateCIBuildRequirements(c, cfg.RepoRootDir); err != nil {
			return err
		}

		pin, err := pinForBuild(cfg, c)
		if err != nil {
			return err
		}

		// Check if the hashrelease has already been published.
		serverCfg := hashreleaseServerConfig(c)
		if published, err := tasks.HashreleasePublished(serverCfg, pin.Hash, c.Bool(ciFlag.Name)); err != nil {
			return fmt.Errorf("hashrelease published: %v", err)
		} else if published {
			// On CI, if the hashrelease has already been published, we exit successfully (return nil).
			// However, on local builds, we just log a warning and continue.
			if c.Bool(ciFlag.Name) {
				logrus.WithField("hash", pin.Hash).Info("hashrelease already been published")
				return nil
			} else {
				logrus.WithField("hash", pin.Hash).Warn("hashrelease already been published but continuing with local build")
			}
		}

		productRegistriesFromFlag := c.StringSlice(registryFlag.Name)

		// Build the operator
		o := pinnedOperator(cfg, c, pin.Operator, pin.ProductVersion)
		if c.Bool(operatorFlagName) {
			if err := operator.Build(o, operatorVariants(c), true,
				operatorBuildOptions(c, filepath.Join(cfg.LogsDir, pin.ProductVersion))...); err != nil {
				return fmt.Errorf("operator build: %w", err)
			}
		}

		// Extract the pinned version as a hashrelease.
		hashrel := pin.Hashrelease(baseHashreleaseOutputDir(cfg.RepoRootDir), false)

		opts := []calico.Option{
			calico.IsHashRelease(),
			calico.WithHashrelease(*hashrel, *serverCfg),
			calico.WithRepoRoot(cfg.RepoRootDir),
			calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
			calico.WithVersion(pin.ProductVersion),
			calico.WithOperatorImage(operator.Registry(o), o.Image, o.Version),
			calico.WithOutputDir(hashrel.Source),
			calico.WithTmpDir(cfg.TmpDir),
			calico.WithLogsDir(filepath.Join(cfg.LogsDir, pin.ProductVersion)),
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
			calico.WithE2EBinaries(c.Bool(e2eBinariesFlag.Name)),
			calico.WithHelmIndex(c.Bool(helmIndexFlagName)),
			calico.WithValidation(c.Bool(validationFlag.Name)),
			calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
		}
		if len(productRegistriesFromFlag) > 0 {
			opts = append(opts, calico.WithImageRegistries(productRegistriesFromFlag))
		}
		r, err := calico.NewManager(opts...)
		if err != nil {
			return fmt.Errorf("calico manager: %w", err)
		}
		if err := r.Build(); err != nil {
			return fmt.Errorf("calico manager build: %w", err)
		}

		// For real releases, release notes are generated prior to building the release.
		// For hash releases, generate a set of release notes and add them to the hashrelease directory.
		if !c.Bool(releaseNotesFlag.Name) {
			logrus.Info("Skipping release notes generation")
		} else if c.String(orgFlag.Name) != utils.ProjectCalicoOrg || c.String(repoFlag.Name) != utils.CalicoRepoName {
			logrus.Warn("Release notes are not supported for non-Calico releases, skipping...")
		} else {
			releaseVersion, err := version.DetermineReleaseVersion(version.New(pin.ProductVersion), c.String(devTagSuffixFlag.Name))
			if err != nil {
				return fmt.Errorf("failed to determine release version: %v", err)
			}
			if _, err := outputs.ReleaseNotes(utils.ProjectCalicoOrg, cfg.RepoRootDir, filepath.Join(hashrel.Source, outputs.ReleaseNotesDir), releaseVersion); err != nil {
				return err
			}
		}

		// Adjust the formatting of the generated outputs to match the legacy hashrelease format.
		return tasks.ReformatHashrelease(pin, hashrel.Source, c.Bool(helmChartsFlagName))
	}
}

// The publish command is used to publish a locally built hashrelease to the hashrelease server.
var hashreleasePublishCommand = func(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "publish",
		Usage:  "Publish a pre-built hashrelease",
		Flags:  hashreleasePublishFlags(),
		Action: hashreleasePublishAction(cfg),
	}
}

var hashreleasePublishAction = func(cfg *Config) func(_ context.Context, c *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("hashrelease-publish.log")

		// Validate flags.
		if err := validateHashreleasePublishFlags(c); err != nil {
			return err
		}

		pin, err := pinForPublish(cfg, c)
		if err != nil {
			return err
		}
		hashrel := pin.Hashrelease(baseHashreleaseOutputDir(cfg.RepoRootDir), c.Bool(latestFlag.Name))

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

		// Push the operator hashrelease first before validation.
		// This is because validation checks all images exists and sends to Image Scan Service
		o := pinnedOperator(cfg, c, hashrel.Operator, hashrel.ProductVersion)
		if c.Bool(operatorFlagName) {
			opts, err := operatorPublishOptions(c, o.Version, hashrel.Source, filepath.Join(cfg.LogsDir, hashrel.ProductVersion))
			if err != nil {
				return fmt.Errorf("operator publish options: %w", err)
			}
			if err := operator.Publish(o, operatorVariants(c), true, opts...); err != nil {
				return fmt.Errorf("operator publish: %w", err)
			}
		}

		opts := []calico.Option{
			calico.IsHashRelease(),
			calico.WithHashrelease(*hashrel, *serverCfg),
			calico.WithRepoRoot(cfg.RepoRootDir),
			calico.WithVersion(hashrel.ProductVersion),
			calico.WithOperatorImage(operator.Registry(o), o.Image, o.Version),
			calico.WithOperator(c.Bool(operatorFlagName)),
			calico.WithOutputDir(hashrel.Source),
			calico.WithTmpDir(cfg.TmpDir),
			calico.WithLogsDir(filepath.Join(cfg.LogsDir, hashrel.ProductVersion)),
			calico.WithGithubOrg(c.String(orgFlag.Name)),
			calico.WithRepoName(c.String(repoFlag.Name)),
			calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
			calico.WithImages(c.Bool(imagesFlagName)),
			calico.WithHelmCharts(c.Bool(helmChartsFlagName)),
			calico.WithPublishHashrelease(c.Bool(publishHashreleaseFlag.Name)),
			calico.WithValidation(c.Bool(validationFlag.Name)),
			calico.WithReleaseBranchValidation(c.Bool(branchCheckFlag.Name)),
			calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
		}
		if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
			opts = append(opts,
				calico.WithImageRegistries(reg),
				calico.WithImageScanning(false, imagescanner.Config{}), // Disable image scanning if using custom registries.
			)
		} else {
			opts = append(opts, calico.WithImageScanning(c.Bool(imageScanFlag.Name), *imageScanningAPIConfig(c)))
		}
		opts = append(opts, calico.WithComponents(pin.Images()))
		if reg := c.StringSlice(helmRegistryFlag.Name); len(reg) > 0 {
			opts = append(opts, calico.WithHelmRegistries(reg))
		}
		r, err := calico.NewManager(opts...)
		if err != nil {
			return fmt.Errorf("calico manager: %w", err)
		}
		if err := r.PublishRelease(); err != nil {
			return fmt.Errorf("publish release: %w", err)
		}

		if c.Bool(imageScanFlag.Name) {
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
	}
}

// hashreleaseBuildFlags returns the flags for the hashrelease build command.
var hashreleaseBuildFlags = func() []cli.Flag {
	f := append(slices.Clone(productFlags), buildStepFlags(true)...)
	f = append(f,
		registryFlag,
		archFlag)
	f = append(f, operatorBuildCommandFlags...)
	f = append(f,
		branchCheckFlag,
		validationFlag)
	return f
}

// validateHashreleaseBuildFlags checks that the flags are set correctly for the hashrelease build command.
var validateHashreleaseBuildFlags = func(c *cli.Command) error {
	if len(c.StringSlice(registryFlag.Name)) > 0 && len(c.StringSlice(operatorRegistryFlag.Name)) == 0 {
		return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag.Name, registryFlag.Name)
	}

	// Hashrelease regenerates manifests before building the OCP bundle.
	if c.Bool(ocpBundleFlag.Name) && !c.Bool(manifestsFlag.Name) {
		return fmt.Errorf("--%s requires --%s on hashrelease builds; either drop --%s or also set --%s",
			ocpBundleFlag.Name, manifestsFlag.Name, inverseFlagName(manifestsFlag.Name), inverseFlagName(ocpBundleFlag.Name))
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
		if c.Bool(imagesFlagName) && len(c.StringSlice(registryFlag.Name)) == 0 {
			logrus.Warn("Building images without specifying a registry will result in images being built with the default registries")
		}

		if len(c.StringSlice(operatorRegistryFlag.Name)) == 0 {
			logrus.Warnf("Local builds should specify an operator registry using %s", operatorRegistryFlag.Name)
		}
	}

	return nil
}

// hashreleasePublishFlags returns the flags for the hashrelease publish command.
var hashreleasePublishFlags = func() []cli.Flag {
	f := append(slices.Clone(productFlags), publishStepFlags(true)...)
	f = append(f,
		registryFlag,
		helmRegistryFlag,
		archFlag,
		publishHashreleaseFlag,
		latestFlag,
		branchCheckFlag,
		validationFlag,
	)
	f = append(f, operatorPublishCommandFlags...)
	f = append(f, imageScanFlags...)
	return f
}

// validateHashreleasePublishFlags checks that the flags are set correctly for the hashrelease publish command.
var validateHashreleasePublishFlags = func(c *cli.Command) error {
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
	if c.Bool(imagesFlagName) {
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
