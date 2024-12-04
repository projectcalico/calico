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

package hashrelease

import (
	"fmt"
	"path/filepath"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/cmd/flags"
	"github.com/projectcalico/calico/release/cmd/release"
	cmd "github.com/projectcalico/calico/release/cmd/utils"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/logger"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

var hashreleaseDir = []string{"release", "_output", "hashrelease"}

func Command(cfg *config.Config) *cli.Command {
	hr := NewCalicoHashreleaseCommand(cfg)
	return hr.Command()
}

func NewCalicoHashreleaseCommand(cfg *config.Config) cmd.ReleaseCommand {
	return &CalicoHashrelease{
		CalicoRelease: release.CalicoRelease{
			ProductName: "calico",
			RepoRootDir: cfg.RepoRootDir,
			TmpDir:      cfg.TmpFolderPath(),
		},
	}
}

type CalicoHashrelease struct {
	release.CalicoRelease
}

func (c *CalicoHashrelease) Command() *cli.Command {
	return &cli.Command{
		Name:        "hashrelease",
		Aliases:     []string{"hr"},
		Usage:       "Build and publish hashreleases.",
		Subcommands: c.Subcommands(),
		Flags: []cli.Flag{
			sshHostFlag, sshUserFlag, sshKeyFlag, sshPortFlag, sshKnownHostsFlag,
		},
	}
}

func (c *CalicoHashrelease) baseOutputDir() string {
	return filepath.Join(append([]string{c.RepoRootDir}, hashreleaseDir...)...)
}

func (c *CalicoHashrelease) OutputDir(ver string) string {
	return filepath.Join(c.baseOutputDir(), ver)
}

func (c *CalicoHashrelease) Subcommands() []*cli.Command {
	return []*cli.Command{
		c.BuildCmd(),
		c.PublishCmd(),
		c.GarbageCollectCmd(),
	}
}

func operatorDir(tmpDir string) string {
	return filepath.Join(tmpDir, operator.DefaultRepoName)
}

func (c *CalicoHashrelease) hashreleaseServerConfig(ctx *cli.Context) hashreleaseserver.Config {
	return hashreleaseserver.Config{
		Host: ctx.String(sshHostFlagName),
		User: ctx.String(sshUserFlagName),
		Key:  ctx.String(sshKeyFlagName),
		Port: ctx.String(sshPortFlagName),
	}
}

func (c *CalicoHashrelease) BuildFlags() []cli.Flag {
	f := flags.ProductFlags
	f = append(f, flags.RegistryFlag,
		flags.BuildImagesFlag(false, c.ProductName),
		flags.ArchFlag)
	f = append(f, flags.OperatorFlags...)
	f = append(f,
		flags.SkipValidationFlag,
		skipBranchCheckFlag,
		flags.GitHubTokenFlag,
	)
	return f
}

func (c *CalicoHashrelease) BuildCmd() *cli.Command {
	return &cli.Command{
		Name:  "build",
		Usage: "Build a hashrelease locally",
		Flags: c.BuildFlags(),
		Action: func(ctx *cli.Context) error {
			logger.Configure("hashrelease-build.log", ctx.Bool(flags.DebugFlagName))
			if err := c.ValidateBuildFlags(ctx); err != nil {
				return err
			}
			if err := c.CloneRepos(ctx); err != nil {
				return err
			}
			pinned := pinnedversion.New(map[string]interface{}{
				"repoRootDir":         c.RepoRootDir,
				"releaseBranchPrefix": ctx.String(flags.ReleaseBranchPrefixFlagName),
				"operator": pinnedversion.OperatorConfig{
					Branch:   ctx.String(flags.OperatorBranchFlagName),
					Image:    ctx.String(flags.OperatorImageFlagName),
					Registry: ctx.String(flags.OperatorRegistryFlagName),
					Dir:      filepath.Join(c.TmpDir, operator.DefaultRepoName),
				},
			}, c.TmpDir)
			_, data, err := pinned.Generate()
			if err != nil {
				return fmt.Errorf("failed to generate pinned version file: %s", err)
			}
			var versions version.Data
			if err := mapstructure.Decode(data["versions"], &versions); err != nil {
				return fmt.Errorf("failed to decode versions: %s", err)
			}
			hash := data["hash"].(string)
			outputDir := c.OutputDir(versions.ProductVersion.FormattedString())

			// Check if the hashrelease already exists
			hrCfg := c.hashreleaseServerConfig(ctx)
			if hrCfg.Valid() {
				if published, err := tasks.HashreleasePublished(&hrCfg, hash, ctx.Bool(flags.CIFlagName)); err != nil {
					return err
				} else if published {
					// On CI, we want it to fail if the hashrelease has already been published.
					// However, on local builds, we just log a warning and continue.
					if ctx.Bool(flags.CIFlagName) {
						return fmt.Errorf("hashrelease %s has already been published", hash)
					} else {
						logrus.Warnf("hashrelease %s has already been published", hash)
					}
				}
			}

			// Build the operator
			if err := c.BuildOperator(ctx, versions.OperatorVersion.FormattedString()); err != nil {
				return fmt.Errorf("failed to build operator: %s", err)
			}

			// Build the product
			opts, err := c.BuildOptions(ctx, data)
			if err != nil {
				return fmt.Errorf("failed to build options: %s", err)
			}
			manager := calico.NewManager(opts...)
			if err := manager.Build(); err != nil {
				return fmt.Errorf("failed to build calico: %s", err)
			}

			// For real releases, release notes are generated prior to building the release.
			// For hash releases, generate a set of release notes and add them to the hashrelease directory.
			releaseVersion, err := version.DetermineReleaseVersion(versions.ProductVersion, ctx.String(flags.DevTagSuffixFlagName))
			if err != nil {
				return fmt.Errorf("failed to determine release version: %v", err)
			}
			if _, err := outputs.ReleaseNotes(utils.CalicoOrg, ctx.String(flags.GitHubTokenFlagName), c.RepoRootDir, outputDir, releaseVersion); err != nil {
				return err
			}

			// Adjust the formatting of the generated outputs to match the legacy hashrelease format.
			return tasks.ReformatHashrelease(outputDir, c.TmpDir)
		},
	}
}

func (c *CalicoHashrelease) BuildOperator(ctx *cli.Context, operatorVersion string) error {
	opts := []operator.Option{
		operator.WithOperatorDirectory(operatorDir(c.TmpDir)),
		operator.WithReleaseBranchPrefix(ctx.String(flags.OperatorReleaseBranchPrefixFlagName)),
		operator.IsHashRelease(),
		operator.WithArchitectures(ctx.StringSlice(flags.ArchFlagName)),
		operator.WithValidate(!ctx.Bool(flags.SkipValidationFlagName)),
		operator.WithReleaseBranchValidation(!ctx.Bool(skipBranchCheckFlagName)),
		operator.WithVersion(operatorVersion),
		operator.WithCalicoDirectory(c.RepoRootDir),
		operator.WithTmpDirectory(c.TmpDir),
	}
	manager := operator.NewManager(opts...)
	return manager.Build()
}

func (c *CalicoHashrelease) BuildOptions(ctx *cli.Context, versions map[string]interface{}) ([]calico.Option, error) {
	var d version.Data
	if err := mapstructure.Decode(versions, &d); err != nil {
		return nil, err
	}
	opts := c.CalicoRelease.BuildOptions(ctx, d.ProductVersion, d.OperatorVersion)
	opts = append(opts,
		calico.IsHashRelease(),
		calico.WithOutputDir(c.OutputDir(d.ProductVersion.FormattedString())),
		calico.WithReleaseBranchValidation(!ctx.Bool(skipBranchCheckFlagName)),
	)
	return opts, nil
}

func (c *CalicoHashrelease) ValidateBuildFlags(ctx *cli.Context) error {
	// If skipping validation, ensure that branch check is disabled
	if ctx.Bool(flags.SkipValidationFlagName) && !ctx.Bool(skipBranchCheckFlagName) {
		return fmt.Errorf("%s must be set if %s is set", skipBranchCheckFlagName, flags.SkipValidationFlagName)
	}

	// If using custom registry for product, ensure that Tigera operator registry is set
	if len(ctx.StringSlice(flags.RegistryFlagName)) > 0 && ctx.String(flags.OperatorRegistryFlagName) == "" {
		return fmt.Errorf("%s must be set if %s is set", flags.OperatorRegistryFlagName, flags.RegistryFlagName)
	}

	// If using custom image name for Tigera operator, ensure that registry is set
	// and vice versa
	if ctx.String(flags.OperatorImageFlagName) != "" && ctx.String(flags.OperatorRegistryFlagName) == "" {
		return fmt.Errorf("%s must be set if %s is set", flags.OperatorRegistryFlag, flags.OperatorImageFlag)
	} else if ctx.String(flags.OperatorRegistryFlagName) != "" && ctx.String(flags.OperatorImageFlagName) == "" {
		return fmt.Errorf("%s must be set if %s is set", flags.OperatorImageFlagName, flags.OperatorRegistryFlagName)
	}

	// CI conditional checks
	if ctx.Bool(flags.CIFlagName) {
		hrCfg := c.hashreleaseServerConfig(ctx)
		if !hrCfg.Valid() {
			return fmt.Errorf("missing hashrelease server configuration")
		}
	} else {
		// Add warning to run non-CI builds with registry flag when building images
		if ctx.Bool(flags.BuildImagesFlagName) && len(ctx.StringSlice(flags.RegistryFlagName)) == 0 {
			logrus.Warnf("Local builds should specify an image registry using the %s flag", flags.RegistryFlagName)
		}
	}

	return nil
}

func (c *CalicoHashrelease) CloneRepos(ctx *cli.Context) error {
	if err := utils.Clone(
		fmt.Sprintf("git@github.com:%s/%s.git", ctx.String(flags.OperatorOrgFlagName), ctx.String(flags.OperatorRepoFlagName)),
		ctx.String(flags.OperatorBranchFlagName), operatorDir(c.TmpDir)); err != nil {
		return fmt.Errorf("failed to clone operator repository: %s", err)
	}
	return nil
}

func (c *CalicoHashrelease) PublishCmd() *cli.Command {
	return &cli.Command{
		Name:  "publish",
		Usage: "Publish a hashrelease to the hashrelease server",
		Flags: c.PublishFlags(),
		Action: func(ctx *cli.Context) error {
			logger.Configure("hashrelease-publish.log", ctx.Bool(flags.DebugFlagName))

			if err := c.ValidatePublishFlags(ctx); err != nil {
				return err
			}

			// Extract the pinned version data as a hashrelease object
			hashrel, err := pinnedversion.New(map[string]interface{}{}, c.TmpDir).LoadHashrelease(c.baseOutputDir())
			if err != nil {
				return fmt.Errorf("failed to load hashrelease: %s", err)
			}
			if ctx.Bool(latestFlagName) {
				hashrel.Latest = true
			}

			// Check if hashrelease already exists in the server
			hrCfg := c.hashreleaseServerConfig(ctx)
			if ctx.Bool(publishHashreleaseFlagName) && hrCfg.Valid() {
				if published, err := tasks.HashreleasePublished(&hrCfg, hashrel.Hash, ctx.Bool(flags.CIFlagName)); err != nil {
					return err
				} else if published {
					return fmt.Errorf("%s hashrelease (%s) has already been published", hashrel.Name, hashrel.Hash)
				}
			}

			// Publish Operator
			if err := c.PublishOperator(ctx); err != nil {
				return fmt.Errorf("failed to publish operator: %s", err)
			}

			// Publish the hashrelease
			opts, err := c.PublishOptions(ctx, hashrel)
			manager := calico.NewManager(opts...)
			if err := manager.PublishRelease(); err != nil {
				return fmt.Errorf("failed to publish hashrelease: %s", err)
			}

			if ctx.Bool(publishHashreleaseFlagName) {
				if err := tasks.AnnouceHashrelease(slack.Config{
					Token:   ctx.String(flags.SlackTokenFlagName),
					Channel: ctx.String(flags.SlackChannelFlagName),
				}, *hashrel, "", c.TmpDir); err != nil {
					return fmt.Errorf("failed to announce hashrelease: %s", err)
				}
			}

			return nil
		},
	}
}

func (c *CalicoHashrelease) PublishOptions(ctx *cli.Context, hashrel *hashreleaseserver.Hashrelease) ([]calico.Option, error) {
	var d version.Data
	if err := mapstructure.Decode(hashrel.Versions, &d); err != nil {
		return nil, err
	}
	opts := c.CalicoRelease.PublishOptions(ctx, d.ProductVersion, d.OperatorVersion)
	opts = append(opts,
		calico.IsHashRelease(),
		calico.WithArchitectures(ctx.StringSlice(flags.ArchFlagName)),
		calico.WithOutputDir(c.OutputDir(d.ProductVersion.FormattedString())),
		calico.WithTmpDir(c.TmpDir),
		calico.WithHashrelease(*hashrel, c.hashreleaseServerConfig(ctx)),
		calico.WithPublishHashrelease(ctx.Bool(publishHashreleaseFlagName)),
		calico.WithImageScanning(!ctx.Bool(skipImageScanFlagName), imagescanner.Config{
			APIURL:  ctx.String(imageScannerAPIFlagName),
			Token:   ctx.String(imageScannerTokenFlagName),
			Scanner: ctx.String(imageScannerSelectFlagName),
		}),
	)
	return opts, nil
}

func (c *CalicoHashrelease) PublishOperator(ctx *cli.Context) error {
	opts := []operator.Option{
		operator.WithOperatorDirectory(operatorDir(c.TmpDir)),
		operator.WithCalicoDirectory(c.RepoRootDir),
		operator.WithTmpDirectory(c.TmpDir),
		operator.IsHashRelease(),
		operator.WithArchitectures(ctx.StringSlice(flags.ArchFlagName)),
		operator.WithValidate(!ctx.Bool(flags.SkipValidationFlagName)),
	}
	manager := operator.NewManager(opts...)
	return manager.Publish()
}

func (c *CalicoHashrelease) PublishFlags() []cli.Flag {
	f := flags.GitFlags
	f = append(f,
		flags.RegistryFlag,
		flags.PublishImagesFlag(false),
		publishHashreleaseFlag,
		latestFlag,
		flags.SkipValidationFlag,
	)
	return append(f, imageScannerFlags...)
}

func (c *CalicoHashrelease) ValidatePublishFlags(ctx *cli.Context) error {
	// Do not allow setting the hashrelease as latest if using custom registries
	if ctx.Bool(latestFlagName) && len(ctx.StringSlice(flags.RegistryFlagName)) > 0 {
		return fmt.Errorf("cannot set hashrelease as latest when using custom registries")
	}

	// If skipping validation, ensure that image scanning is disabled
	if ctx.Bool(flags.SkipValidationFlagName) && !ctx.Bool(skipImageScanFlagName) {
		return fmt.Errorf("%s must be set if %s is set", skipImageScanFlagName, flags.SkipValidationFlagName)
	}

	hrCfg := c.hashreleaseServerConfig(ctx)
	if !hrCfg.Valid() && ctx.Bool(publishHashreleaseFlagName) {
		return fmt.Errorf("missing hashrelease server configuration")
	}

	return nil
}

func (c *CalicoHashrelease) GarbageCollectCmd() *cli.Command {
	return &cli.Command{
		Name:    "garbage-collect",
		Usage:   "Clean up older hashreleases in the hashrelease server",
		Aliases: []string{"gc"},
		Action: func(context *cli.Context) error {
			logger.Configure("hashrelease-garbage-collect.log", context.Bool(flags.DebugFlagName))
			return hashreleaseserver.CleanOldHashreleases(&hashreleaseserver.Config{
				Host:       context.String(sshHostFlagName),
				User:       context.String(sshUserFlagName),
				Key:        context.String(sshKeyFlagName),
				Port:       context.String(sshPortFlagName),
				KnownHosts: context.String(sshKnownHostsFlagName),
			})
		},
	}
}
