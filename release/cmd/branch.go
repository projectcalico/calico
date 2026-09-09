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
	"fmt"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/branch"
	"github.com/projectcalico/calico/release/internal/utils"
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
				mainBranchFlag,
				releaseBranchPrefixFlag,
				devTagSuffixFlag,
				localFlag,
				validationFlag,
				planFlag,
				skipFlag(branch.StepNames()),
			},
			Action: func(_ context.Context, c *cli.Command) error {
				configureLogging("branch-cut.log")

				calicoManager := calico.NewManager(
					calico.WithGithubOrg(c.String(orgFlag.Name)),
					calico.WithRepoName(c.String(repoFlag.Name)),
					calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
					calico.WithRepoRoot(cfg.RepoRootDir),
					calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					calico.WithMainBranch(c.String(mainBranchFlag.Name)),
					calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
					calico.WithValidation(c.Bool(validationFlag.Name)),
					calico.WithGitRef(!c.Bool(localFlag.Name)),
					calico.WithBranchCutOptions(calico.CutOptions{
						Plan:        c.Bool(planFlag.Name),
						Skip:        skipSet(c.StringSlice(skipFlagName)),
						BranchCheck: c.Bool(branchCheckFlagName),
					}),
				)

				return calicoManager.CutBranch()
			},
		},
	}
}

func skipSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}
