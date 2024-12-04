// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance branch.With the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// branch.WithOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package branch

import (
	"fmt"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/cmd/flags"
	cmd "github.com/projectcalico/calico/release/cmd/utils"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/logger"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var (
	publishBranchFlagName = "git-publish"
	publishBranchFlag     = &cli.BoolFlag{
		Name:  publishBranchFlagName,
		Usage: "Publish the branch to the remote repository",
		Value: true,
	}

	baseBranchFlagName = "main-branch"
	baseBranchFlag     = &cli.StringFlag{
		Name:  baseBranchFlagName,
		Usage: "Branch to cut the release branch off of",
		Value: utils.DefaultBranch,
	}

	streamFlagName = "release-stream"
	streamFlag     = &cli.StringFlag{
		Name:  streamFlagName,
		Usage: "Release stream to use for the release",
	}
)

func Command(cfg *config.Config) *cli.Command {
	b := NewBranchCommand(cfg)
	return b.Command()
}

func NewBranchCommand(cfg *config.Config) cmd.Command {
	return &Branch{
		RepoRootDir: cfg.RepoRootDir,
		TmpDir:      cfg.TmpFolderPath(),
	}
}

type Branch struct {
	RepoRootDir string
	TmpDir      string
}

func (b *Branch) Command() *cli.Command {
	return &cli.Command{
		Name:        "branch",
		Aliases:     []string{"br"},
		Usage:       "Manage branches",
		Subcommands: b.Subcommands(),
	}
}

func (b *Branch) Subcommands() []*cli.Command {
	return []*cli.Command{
		b.CutCmd(),
	}
}

func (b *Branch) CutCmd() *cli.Command {
	return &cli.Command{
		Name:  "cut",
		Usage: fmt.Sprintf("Cut a new release branch from %s", utils.DefaultBranch),
		Flags: []cli.Flag{
			flags.RepoRemoteFlag,
			flags.ReleaseBranchPrefixFlag,
			flags.DevTagSuffixFlag,
			baseBranchFlag,
			publishBranchFlag,
			flags.SkipValidationFlag,
		},
		Action: func(ctx *cli.Context) error {
			logger.Configure("cut-branch.log", ctx.Bool(flags.DebugFlagName))

			m := branch.NewManager(
				branch.WithRepoRoot(b.RepoRootDir),
				branch.WithRepoRemote(ctx.String(flags.RepoRemoteFlagName)),
				branch.WithMainBranch(ctx.String(baseBranchFlagName)),
				branch.WithDevTagIdentifier(ctx.String(flags.DevTagSuffixFlagName)),
				branch.WithReleaseBranchPrefix(ctx.String(flags.ReleaseBranchPrefixFlagName)),
				branch.WithValidate(!ctx.Bool(flags.SkipValidationFlagName)),
				branch.WithPublish(ctx.Bool(publishBranchFlagName)),
			)
			return m.CutReleaseBranch()
		},
	}
}

func (b *Branch) OperatorCutCmd() *cli.Command {
	return &cli.Command{
		Name:  "cut-operator",
		Usage: "Cut a new operator release branch from the main branch",
		Flags: []cli.Flag{
			flags.OperatorGitRemoteFlag,
			flags.OperatorOrgFlag,
			flags.OperatorRepoFlag,
			flags.OperatorReleaseBranchPrefixFlag,
			flags.OperatorDevTagSuffixFlag,
			baseBranchFlag,
			publishBranchFlag,
			flags.SkipValidationFlag,
		},
		Action: func(ctx *cli.Context) error {
			logger.Configure("cut-operator-branch.log", ctx.Bool(flags.DebugFlagName))

			operatorDir := filepath.Join(b.TmpDir, "operator")

			// Clone the operator repository
			if err := utils.Clone(
				fmt.Sprintf("git@github.com:%s/%s.git", ctx.String(flags.OperatorOrgFlagName), ctx.String(flags.OperatorRepoFlagName)),
				ctx.String(flags.OperatorBranchFlagName), operatorDir); err != nil {
				return fmt.Errorf("failed to clone operator repository: %s", err)
			}

			opts := []operator.Option{
				operator.WithOperatorDirectory(operatorDir),
				operator.WithRepoRemote(ctx.String(flags.OperatorGitRemoteFlagName)),
				operator.WithGithubOrg(ctx.String(flags.OperatorOrgFlagName)),
				operator.WithRepoName(ctx.String(flags.OperatorRepoFlagName)),
				operator.WithBranch(ctx.String(baseBranchFlagName)),
				operator.WithDevTagIdentifier(ctx.String(flags.OperatorDevTagSuffixFlagName)),
				operator.WithReleaseBranchPrefix(ctx.String(flags.OperatorReleaseBranchPrefixFlagName)),
				operator.WithValidate(!ctx.Bool(flags.SkipValidationFlagName)),
				operator.WithPublish(ctx.Bool(publishBranchFlagName)),
			}
			if ctx.String(streamFlagName) == "" {
				opts = append(opts, operator.WithReleaseStream(ctx.String(streamFlagName)))
			}

			m := operator.NewManager(opts...)
			return m.CutBranch()
		},
	}
}
