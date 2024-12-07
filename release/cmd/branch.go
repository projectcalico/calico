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

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

// The branch command suite is used to manage branches.
func branchCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:        "branch",
		Aliases:     []string{"br"},
		Usage:       "Manage branches.",
		Subcommands: branchSubCommands(cfg),
	}
}

func branchSubCommands(cfg *config.Config) []*cli.Command {
	return []*cli.Command{
		// Cut a new release branch
		{
			Name:  "cut",
			Usage: fmt.Sprintf("Cut a new release branch from %s", utils.DefaultBranch),
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip release branch cut validations", Value: false},
				&cli.BoolFlag{Name: publishBranchFlag, Usage: "Push branch and tag to git. If false, all changes are local.", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging("cut-branch.log")
				m := branch.NewManager(branch.WithRepoRoot(cfg.RepoRootDir),
					branch.WithRepoRemote(cfg.GitRemote),
					branch.WithMainBranch(utils.DefaultBranch),
					branch.WithDevTagIdentifier(cfg.DevTagSuffix),
					branch.WithReleaseBranchPrefix(cfg.RepoReleaseBranchPrefix),
					branch.WithValidate(!c.Bool(skipValidationFlag)),
					branch.WithPublish(c.Bool(publishBranchFlag)))
				return m.CutReleaseBranch()
			},
		},
		// Cut a new operator release branch
		{
			Name:  "cut-operator",
			Usage: fmt.Sprintf("Cut a new operator release branch from %s", utils.DefaultBranch),
			Flags: []cli.Flag{
				&cli.StringFlag{Name: operatorOrgFlag, Usage: "Operator git organization", EnvVars: []string{"OPERATOR_GIT_ORGANIZATION"}, Value: config.OperatorDefaultOrg},
				&cli.StringFlag{Name: operatorRepoFlag, Usage: "Operator git repository", EnvVars: []string{"OPERATOR_GIT_REPO"}, Value: config.OperatorDefaultRepo},
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip release branch cut validations", Value: false},
				&cli.BoolFlag{Name: publishBranchFlag, Usage: "Push branch and tag to git. If false, all changes are local.", Value: false},
				&cli.StringFlag{Name: sourceBranchFlag, Usage: "The branch to cut the operator release from", Value: utils.DefaultBranch},
				&cli.StringFlag{Name: newBranchFlag, Usage: fmt.Sprintf("The new version for the branch to create i.e. vX.Y to create a %s-vX.Y branch", cfg.Operator.RepoReleaseBranchPrefix), Value: ""},
			},
			Action: func(c *cli.Context) error {
				configureLogging("cut-operator-branch.log")
				if c.String(newBranchFlag) == "" {
					logrus.Warn("No branch version specified, will cut branch based on latest dev tag")
				}
				// Clone the operator repository
				if err := utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", c.String(operatorOrgFlag), c.String(operatorRepoFlag)), cfg.Operator.Branch, cfg.Operator.Dir); err != nil {
					return err
				}
				// Create operator manager
				m := operator.NewManager(
					operator.WithOperatorDirectory(cfg.Operator.Dir),
					operator.WithRepoRemote(cfg.Operator.GitRemote),
					operator.WithGithubOrg(c.String(operatorOrgFlag)),
					operator.WithRepoName(c.String(operatorRepoFlag)),
					operator.WithBranch(utils.DefaultBranch),
					operator.WithDevTagIdentifier(cfg.Operator.DevTagSuffix),
					operator.WithReleaseBranchPrefix(cfg.Operator.RepoReleaseBranchPrefix),
					operator.WithValidate(!c.Bool(skipValidationFlag)),
					operator.WithPublish(c.Bool(publishBranchFlag)),
				)
				return m.CutBranch(c.String(newBranchFlag))
			},
		},
	}
}
