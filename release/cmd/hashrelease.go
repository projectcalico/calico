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
		Name:        "hashrelease",
		Aliases:     []string{"hr"},
		Usage:       "Build and publish hashreleases.",
		Flags:       hashreleaseServerFlags,
		Subcommands: hashreleaseSubCommands(cfg),
	}
}

func hashreleaseSubCommands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		// The build command is used to produce a new local hashrelease in the output directory.
		{
			Name:  "build",
			Usage: "Build a hashrelease locally",
			Flags: hashreleaseBuildFlags(),
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-build.log")

				// Validate flags.
				if err := validateHashreleaseBuildFlags(c); err != nil {
					return err
				}

				// Clone the operator repository.
				operatorDir := filepath.Join(cfg.TmpDir, operator.DefaultRepoName)
				err := operator.Clone(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name), operatorDir)
				if err != nil {
					return fmt.Errorf("failed to clone operator repository: %v", err)
				}

				// Define the base hashrelease directory.
				baseHashreleaseDir := baseHashreleaseOutputDir(cfg.RepoRootDir)

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
				if published, err := tasks.HashreleasePublished(hashreleaseServerConfig(c), data.Hash(), c.Bool(ciFlag.Name)); err != nil {
					return fmt.Errorf("failed to check if hashrelease has been published: %v", err)
				} else if published {
					// On CI, we want it to fail if the hashrelease has already been published.
					// However, on local builds, we just log a warning and continue.
					if c.Bool(ciFlag.Name) {
						return fmt.Errorf("hashrelease %s has already been published", data.Hash())
					} else {
						logrus.Warnf("hashrelease %s has already been published", data.Hash())
					}
				}

				// Build the operator
				operatorOpts := []operator.Option{
					operator.WithOperatorDirectory(operatorDir),
					operator.WithReleaseBranchPrefix(c.String(operatorReleaseBranchPrefixFlag.Name)),
					operator.IsHashRelease(),
					operator.WithArchitectures(c.StringSlice(archFlag.Name)),
					operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
					operator.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
					operator.WithVersion(data.OperatorVersion()),
					operator.WithCalicoDirectory(cfg.RepoRootDir),
					operator.WithTempDirectory(cfg.TmpDir),
				}
				if !c.Bool(skipOperatorFlag.Name) {
					o := operator.NewManager(operatorOpts...)
					if err := o.Build(); err != nil {
						return err
					}
				}

				// Define the hashrelease directory using the hash from the pinned file.
				hashreleaseDir := filepath.Join(baseHashreleaseDir, data.Hash())

				// Configure a release builder using the generated versions, and use it
				// to build a Calico release.
				pinnedOpts, err := pinned.ManagerOptions()
				if err != nil {
					return fmt.Errorf(("failed to retrieve pinned version options for manager: %v"), err)
				}
				opts := append(pinnedOpts,
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.IsHashRelease(),
					calico.WithOutputDir(hashreleaseDir),
					calico.WithBuildImages(c.Bool(buildHashreleaseImageFlag.Name)),
					calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
					calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithArchitectures(c.StringSlice(archFlag.Name)),
				)
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
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
					if _, err := outputs.ReleaseNotes(utils.ProjectCalicoOrg, c.String(githubTokenFlag.Name), cfg.RepoRootDir, filepath.Join(hashreleaseDir, releaseNotesDir), releaseVersion); err != nil {
						return err
					}
				}

				// Adjsut the formatting of the generated outputs to match the legacy hashrelease format.
				return tasks.ReformatHashrelease(hashreleaseDir, cfg.TmpDir)
			},
		},

		// The publish command is used to publish a locally built hashrelease to the hashrelease server.
		{
			Name:  "publish",
			Usage: "Publish a pre-built hashrelease",
			Flags: hashreleasePublishFlags(),
			Action: func(c *cli.Context) error {
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
					return fmt.Errorf("%s hashrelease (%s) has already been published", hashrel.Name, hashrel.Hash)
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
					calico.WithHashrelease(*hashrel, *serverCfg),
					calico.WithPublishImages(c.Bool(publishHashreleaseImageFlag.Name)),
					calico.WithPublishHashrelease(c.Bool(publishHashreleaseFlag.Name)),
					calico.WithImageScanning(!c.Bool(skipImageScanFlag.Name), *imageScanningAPIConfig(c)),
				}
				if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
					opts = append(opts, calico.WithImageRegistries(reg))
				}
				// Note: We only need to check that the correct images exist if we haven't built them ourselves.
				// So, skip this check if we're configured to build and publish images from the local codebase.
				if !c.Bool(publishHashreleaseImageFlag.Name) {
					components, err := pinnedversion.RetrieveImageComponents(cfg.TmpDir)
					if err != nil {
						return fmt.Errorf("failed to retrieve images for the hashrelease: %v", err)
					}
					opts = append(opts, calico.WithComponents(components))
				}
				r := calico.NewManager(opts...)
				if err := r.PublishRelease(); err != nil {
					return err
				}

				// Send a slack message to notify that the hashrelease has been published.
				if c.Bool(publishHashreleaseFlag.Name) {
					if err := tasks.HashreleaseSlackMessage(slackConfig(c), hashrel, !c.Bool(skipImageScanFlag.Name), ciJobURL(c), cfg.TmpDir); err != nil {
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
			Flags:   []cli.Flag{maxHashreleasesFlag},
			Action: func(c *cli.Context) error {
				configureLogging("hashrelease-garbage-collect.log")
				return hashreleaseserver.CleanOldHashreleases(hashreleaseServerConfig(c), c.Int(maxHashreleasesFlag.Name))
			},
		},
	}
}

// hashreleaseBuildFlags returns the flags for the hashrelease build command.
func hashreleaseBuildFlags() []cli.Flag {
	f := append(productFlags,
		registryFlag,
		archFlag)
	f = append(f, operatorBuildFlags...)
	f = append(f,
		skipOperatorFlag,
		skipBranchCheckFlag,
		skipValidationFlag,
		buildHashreleaseImageFlag,
		githubTokenFlag)
	return f
}

// validateHashreleaseBuildFlags checks that the flags are set correctly for the hashrelease build command.
func validateHashreleaseBuildFlags(c *cli.Context) error {
	// If using a custom registry for product, ensure operator is also using a custom registry.
	if len(c.StringSlice(registryFlag.Name)) > 0 && c.String(operatorRegistryFlag.Name) == "" {
		return fmt.Errorf("%s must be set if %s is set", operatorRegistryFlag, registryFlag)
	}

	// CI condtional checks.
	if c.Bool(ciFlag.Name) {
		if !hashreleaseServerConfig(c).Valid() {
			return fmt.Errorf("missing hashrelease server configuration, must set %s, %s, %s, %s, and %s",
				sshHostFlag, sshUserFlag, sshKeyFlag, sshPortFlag, sshKnownHostsFlag)
		}
	} else {
		// If building images, log a warning if no registry is specified.
		if c.Bool(buildHashreleaseImageFlag.Name) && len(c.StringSlice(registryFlag.Name)) == 0 {
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
		archFlag,
		publishHashreleaseImageFlag,
		publishHashreleaseFlag,
		latestFlag,
		skipOperatorFlag,
		skipValidationFlag,
		skipImageScanFlag)
	f = append(f, imageScannerAPIFlags...)
	return f
}

// validateHashreleasePublishFlags checks that the flags are set correctly for the hashrelease publish command.
func validateHashreleasePublishFlags(c *cli.Context) error {
	// If publishing the hashrelease, then the hashrelease server configuration must be set.
	if c.Bool(publishHashreleaseFlag.Name) && !hashreleaseServerConfig(c).Valid() {
		return fmt.Errorf("missing hashrelease server configuration, must set %s, %s, %s, %s, and %s",
			sshHostFlag, sshUserFlag, sshKeyFlag, sshPortFlag, sshKnownHostsFlag)
	}

	// If using a custom registry, do not allow setting the hashrelease as latest.
	if len(c.StringSlice(registryFlag.Name)) > 0 && c.Bool(latestFlag.Name) {
		return fmt.Errorf("cannot set hashrelease as latest when using a custom registry")
	}

	// If skipValidationFlag is set, then skipImageScanFlag must also be set.
	if c.Bool(skipValidationFlag.Name) && !c.Bool(skipImageScanFlag.Name) {
		return fmt.Errorf("%s must be set if %s is set", skipImageScanFlag, skipValidationFlag)
	}
	return nil
}

// ciJobURL returns the URL to the CI job if the command is running on CI.
func ciJobURL(c *cli.Context) string {
	if !c.Bool(ciFlag.Name) {
		return ""
	}
	return fmt.Sprintf("%s/jobs/%s", c.String(ciBaseURLFlag.Name), c.String(ciJobIDFlag.Name))
}

func hashreleaseServerConfig(c *cli.Context) *hashreleaseserver.Config {
	return &hashreleaseserver.Config{
		Host:       c.String(sshHostFlag.Name),
		User:       c.String(sshUserFlag.Name),
		Key:        c.String(sshKeyFlag.Name),
		Port:       c.String(sshPortFlag.Name),
		KnownHosts: c.String(sshKnownHostsFlag.Name),
	}
}

func imageScanningAPIConfig(c *cli.Context) *imagescanner.Config {
	return &imagescanner.Config{
		APIURL:  c.String(imageScannerAPIFlag.Name),
		Token:   c.String(imageScannerTokenFlag.Name),
		Scanner: c.String(imageScannerSelectFlag.Name),
	}
}
