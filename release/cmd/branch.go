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

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

// The branch command suite is used to manage branches.
func branchCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:        "branch",
		Aliases:     []string{"br"},
		Usage:       "Manage branches.",
		Subcommands: branchSubCommands(cfg),
	}
}

func branchSubCommands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		// Cut a new release branch
		{
			Name:  "cut",
			Usage: fmt.Sprintf("Cut a new release branch from %s", utils.DefaultBranch),
			Flags: []cli.Flag{
				orgFlag,
				repoFlag,
				repoRemoteFlag,
				baseBranchFlag,
				releaseBranchPrefixFlag,
				devTagSuffixFlag,
				publishBranchFlag,
				skipValidationFlag,
			},
			Action: func(c *cli.Context) error {
				configureLogging("cut-branch.log")

				m := branch.NewManager(
					branch.WithRepoRoot(cfg.RepoRootDir),
					branch.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					branch.WithMainBranch(c.String(mainBranchFlag.Name)),
					branch.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
					branch.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					branch.WithValidate(!c.Bool(skipValidationFlag.Name)),
					branch.WithPublish(c.Bool(publishBranchFlag.Name)))
				return m.CutReleaseBranch()
			},
		},
		// Cut a new operator release branch
		{
			Name:  "cut-operator",
			Usage: fmt.Sprintf("Cut a new operator release branch from %s", utils.DefaultBranch),
			Flags: append(operatorGitFlags,
				operatorBaseBranchFlag,
				operatorReleaseBranchPrefixFlag,
				operatorDevTagSuffixFlag,
				newBranchFlag,
				publishBranchFlag,
				skipValidationFlag,
			),
			Action: func(c *cli.Context) error {
				configureLogging("cut-operator-branch.log")

				// Warn if the new branch is not the default base branch
				if c.String(newBranchFlag.Name) != newBranchFlag.Value {
					logrus.Warnf("The new branch will be created from %s which is not the default branch %s", c.String(newBranchFlag.Name), newBranchFlag.Value)
				}

				// Clone the operator repository
				operatorDir := filepath.Join(cfg.TmpDir, operator.DefaultRepoName)
				if err := operator.Clone(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBaseBranchFlag.Name), operatorDir); err != nil {
					return err
				}

				// Create operator manager
				m := operator.NewManager(
					operator.WithOperatorDirectory(operatorDir),
					operator.WithRepoRemote(c.String(operatorRepoRemoteFlag.Name)),
					operator.WithGithubOrg(c.String(operatorOrgFlag.Name)),
					operator.WithRepoName(c.String(operatorRepoFlag.Name)),
					operator.WithBranch(operatorBaseBranchFlag.Name),
					operator.WithDevTagIdentifier(operatorDevTagSuffixFlag.Name),
					operator.WithReleaseBranchPrefix(c.String(operatorReleaseBranchPrefixFlag.Name)),
					operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
					operator.WithPublish(c.Bool(publishBranchFlag.Name)),
				)

				return m.CutBranch(c.String(newBranchFlag.Name))
			},
		},
	}
}
