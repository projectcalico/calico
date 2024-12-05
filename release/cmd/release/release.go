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

package release

import (
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/cmd/flags"
	cmd "github.com/projectcalico/calico/release/cmd/utils"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/logger"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

var relativeUploadDir = []string{"release", "_output", "upload"}

func Command(cfg *config.Config) *cli.Command {
	rel := NewCalicoReleaseComand(cfg)
	return rel.Command()
}

func NewCalicoReleaseComand(cfg *config.Config) cmd.ReleaseCommand {
	return &CalicoRelease{
		ProductName: "calico",
		RepoRootDir: cfg.RepoRootDir,
		TmpDir:      cfg.TmpFolderPath(),
	}
}

type CalicoRelease struct {
	ProductName string
	RepoRootDir string
	TmpDir      string
}

func (c *CalicoRelease) Command() *cli.Command {
	return &cli.Command{
		Name:        "release",
		Aliases:     []string{"rel"},
		Usage:       "Build and publish public releases",
		Subcommands: c.Subcommands(),
	}
}

func (c *CalicoRelease) OutputDir(ver string) string {
	baseOutputDir := filepath.Join(append([]string{c.RepoRootDir}, relativeUploadDir...)...)
	return filepath.Join(baseOutputDir, ver)
}

func (c *CalicoRelease) Subcommands() []*cli.Command {
	return []*cli.Command{
		c.ReleaseNotesCmd(),
		c.BuildCmd(),
		c.PublishCmd(),
	}
}

func (c *CalicoRelease) ReleaseNotesCmd() *cli.Command {
	return &cli.Command{
		Name:    "release-notes",
		Aliases: []string{"rn"},
		Usage:   "Generate release notes",
		Flags: []cli.Flag{
			flags.OrgFlag,
			flags.DevTagSuffixFlag,
			flags.GitHubTokenFlag,
		},
		Action: func(ctx *cli.Context) error {
			logger.Configure("release-notes.log", ctx.Bool(flags.DebugFlagName))

			ver, err := version.DetermineReleaseVersion(version.GitVersion(), ctx.String(flags.DevTagSuffixFlagName))
			if err != nil {
				return fmt.Errorf("failed to determine release version: %w", err)
			}

			f, err := outputs.ReleaseNotes(ctx.String(flags.OrgFlagName), ctx.String(flags.GitHubTokenFlagName), c.RepoRootDir, c.RepoRootDir, ver)
			if err != nil {
				return fmt.Errorf("failed to generate release notes: %w", err)
			}
			logrus.WithField("release-notes", f).Info("Release notes generated")
			logrus.Info("Please review for accuracy, and format appropriately before releasing.")

			return nil
		},
	}
}

func (c *CalicoRelease) BuildFlags() []cli.Flag {
	f := flags.ProductFlags
	f = append(f,
		flags.BuildImagesFlag(true, c.ProductName),
		flags.ArchFlag,
		flags.RegistryFlag,
		flags.SkipValidationFlag,
	)
	return f
}

func (c *CalicoRelease) BuildCmd() *cli.Command {
	return &cli.Command{
		Name:  "build",
		Usage: "Build an official release",
		Flags: c.BuildFlags(),
		Action: func(ctx *cli.Context) error {
			logger.Configure("release-build.log", ctx.Bool(flags.DebugFlagName))

			// Determine the versions to use for the release.
			ver, err := version.DetermineReleaseVersion(version.GitVersion(), ctx.String(flags.DevTagSuffixFlagName))
			if err != nil {
				return fmt.Errorf("failed to determine release version: %w", err)
			}
			operatorVer, err := version.DetermineOperatorVersion(c.RepoRootDir)
			if err != nil {
				return fmt.Errorf("failed to determine operator version: %w", err)
			}

			opts := c.BuildOptions(ctx, ver, operatorVer)
			manager := calico.NewManager(opts...)
			return manager.Build()
		},
	}
}

func (c *CalicoRelease) BuildOptions(ctx *cli.Context, ver version.Version, operatorVer version.Version) []calico.Option {
	opts := []calico.Option{
		calico.WithRepoRoot(c.RepoRootDir),
		calico.WithReleaseBranchPrefix(ctx.String(flags.ReleaseBranchPrefixFlagName)),
		calico.WithVersions(version.Data{
			ProductVersion:  ver,
			OperatorVersion: operatorVer,
		}),
		calico.WithGithubOrg(ctx.String(flags.OrgFlagName)),
		calico.WithRepoName(ctx.String(flags.RepoFlagName)),
		calico.WithRepoRemote(ctx.String(flags.RepoRemoteFlagName)),
		calico.WithBuildImages(ctx.Bool(flags.BuildImagesFlagName)),
		calico.WithArchitectures(ctx.StringSlice(flags.ArchFlagName)),
		calico.WithOutputDir(c.OutputDir(ver.FormattedString())),
		calico.WithValidate(!ctx.Bool(flags.SkipValidationFlagName)),
	}
	if reg := ctx.StringSlice(flags.RegistryFlagName); len(reg) > 0 {
		opts = append(opts, calico.WithImageRegistries(reg))
	}
	return opts
}

func (c *CalicoRelease) PublishFlags() []cli.Flag {
	f := flags.ProductFlags
	f = append(f,
		flags.RegistryFlag,
		flags.PublishImagesFlag(true),
		publishGitTagFlag,
		publishGitHubReleaseFlag,
		flags.SkipValidationFlag,
	)
	return f
}

func (c *CalicoRelease) PublishCmd() *cli.Command {
	return &cli.Command{
		Name:  "publish",
		Usage: "Publish an official release",
		Flags: c.PublishFlags(),
		Action: func(ctx *cli.Context) error {
			logger.Configure("release-publish.log", ctx.Bool(flags.DebugFlagName))

			// Determine the versions to use for the release.
			ver, operatorVer, err := version.VersionsFromManifests(c.RepoRootDir)
			if err != nil {
				return fmt.Errorf("failed to determine release versions: %w", err)
			}

			opts := c.PublishOptions(ctx, ver, operatorVer)
			manager := calico.NewManager(opts...)
			return manager.PublishRelease()
		},
	}
}

func (c *CalicoRelease) PublishOptions(ctx *cli.Context, ver version.Version, operatorVer version.Version) []calico.Option {
	opts := []calico.Option{
		calico.WithRepoRoot(c.RepoRootDir),
		calico.WithVersions(version.Data{
			ProductVersion:  ver,
			OperatorVersion: operatorVer,
		}),
		calico.WithGithubOrg(ctx.String(flags.OrgFlagName)),
		calico.WithRepoName(ctx.String(flags.RepoFlagName)),
		calico.WithRepoRemote(ctx.String(flags.RepoRemoteFlagName)),
		calico.WithOutputDir(c.OutputDir(ver.FormattedString())),
		calico.WithPublishImages(ctx.Bool(flags.PublishImagesFlagName)),
		calico.WithPublishGitTag(ctx.Bool(publishGitTagFlagName)),
		calico.WithPublishGithubRelease(ctx.Bool(publishGitHubReleaseFlagName)),
		calico.WithValidate(!ctx.Bool(flags.SkipValidationFlagName)),
	}
	if reg := ctx.StringSlice(flags.RegistryFlagName); len(reg) > 0 {
		opts = append(opts, calico.WithImageRegistries(reg))
	}
	return opts
}
