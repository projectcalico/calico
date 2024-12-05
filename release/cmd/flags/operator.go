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

package flags

import (
	"github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var OperatorFlags = []cli.Flag{
	OperatorOrgFlag, OperatorRepoFlag, OperatorBranchFlag, OperatorGitRemoteFlag,
	OperatorReleaseBranchPrefixFlag, OperatorDevTagSuffixFlag,
	OperatorRegistryFlag, OperatorImageFlag,
}

// Git Flags
var (
	OperatorOrgFlagName = "operator-org"
	OperatorOrgFlag     = &cli.StringFlag{
		Name:  OperatorOrgFlagName,
		Usage: "The GitHub organization to use for Tigera operator release",
		Value: operator.DefaultOrg,
	}

	OperatorRepoFlagName = "operator-repo"
	OperatorRepoFlag     = &cli.StringFlag{
		Name:  OperatorRepoFlagName,
		Usage: "The GitHub repository to use for Tigera operator release",
		Value: operator.DefaultRepoName,
	}

	OperatorGitRemoteFlagName = "operator-git-remote"
	OperatorGitRemoteFlag     = &cli.StringFlag{
		Name:  OperatorGitRemoteFlagName,
		Usage: "The remote for Tigera operator git repository",
		Value: operator.DefaultRemote,
	}

	OperatorBranchFlagName = "operator-branch"
	OperatorBranchFlag     = &cli.StringFlag{
		Name:  OperatorBranchFlagName,
		Usage: "The branch to use for Tigera operator release",
		Value: operator.DefaultBranchName,
	}
)

var (
	OperatorReleaseBranchPrefixFlagName = "operator-release-branch-prefix"
	OperatorReleaseBranchPrefixFlag     = &cli.StringFlag{
		Name:  OperatorReleaseBranchPrefixFlagName,
		Usage: "The stardard prefix used to denote Tigera operator release branches",
		Value: operator.DefaultReleaseBranchPrefix,
	}

	OperatorDevTagSuffixFlagName = "operator-dev-tag-suffix"
	OperatorDevTagSuffixFlag     = &cli.StringFlag{
		Name:  OperatorDevTagSuffixFlagName,
		Usage: "The suffix used to denote development tags for Tigera operator",
		Value: operator.DefaultDevTagSuffix,
	}
)

// Image flags
var (
	OperatorRegistryFlagName = "operator-registry"
	OperatorRegistryFlag     = &cli.StringFlag{
		Name:    OperatorRegistryFlagName,
		Usage:   "The registry to use for Tigera operator release",
		EnvVars: []string{"OPERATOR_REGISTRY"},
		Value:   operator.DefaultRegistry,
	}

	OperatorImageFlagName = "operator-image"
	OperatorImageFlag     = &cli.StringFlag{
		Name:    OperatorImageFlagName,
		Usage:   "The image name to use for Tigera operator release",
		EnvVars: []string{"OPERATOR_IMAGE"},
		Value:   operator.DefaultImage,
	}
)
