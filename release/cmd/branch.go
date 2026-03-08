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
	"fmt"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

// The branch command suite is used to manage branches.
func branchCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:     "branch",
		Aliases:  []string{"br"},
		Usage:    "Manage branches.",
		Commands: branchSubCommands(cfg),
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
				operatorBranchFlag,
				gitPublishFlag,
				skipValidationFlag,
			},
			Action: func(_ context.Context, c *cli.Command) error {
				configureLogging("branch-cut.log")

				calicoManager := calico.NewManager(
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.WithOperatorBranch(c.String(operatorBranchFlag.Name)),
					calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				)

				m := branch.NewManager(
					branch.WithRepoRoot(cfg.RepoRootDir),
					branch.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					branch.WithMainBranch(c.String(baseBranchFlag.Name)),
					branch.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
					branch.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					branch.WithRepoManager(calicoManager),
					branch.WithValidate(!c.Bool(skipValidationFlag.Name)),
					branch.WithPublish(c.Bool(gitPublishFlag.Name)))
				return m.CutReleaseBranch()
			},
		},
	}
}
