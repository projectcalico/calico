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
	"fmt"

	"github.com/urfave/cli/v2"
)

// Git flags
var (
	OrgFlagName = "org"
	OrgFlag     = &cli.StringFlag{
		Name:    "org",
		Usage:   "The GitHub organization to use for the release",
		EnvVars: []string{"ORGANIZATION"},
		Value:   "projectcalico",
	}

	RepoFlagName = "repo"
	RepoFlag     = &cli.StringFlag{
		Name:    "repo",
		Usage:   "The GitHub repository to use for the release",
		EnvVars: []string{"GIT_REPO"},
		Value:   "calico",
	}

	RepoRemoteFlagName = "remote"
	RepoRemoteFlag     = &cli.StringFlag{
		Name:    "remote",
		Usage:   "The remote for the git repository",
		EnvVars: []string{"GIT_REMOTE"},
		Value:   "origin",
	}

	GitFlags = []cli.Flag{OrgFlag, RepoFlag, RepoRemoteFlag}
)

var ProductFlags = append(GitFlags, []cli.Flag{
	ReleaseBranchPrefixFlag,
	DevTagSuffixFlag,
}...)

var (
	ReleaseBranchPrefixFlagName = "release-branch-prefix"
	ReleaseBranchPrefixFlag     = &cli.StringFlag{
		Name:  "release-branch-prefix",
		Usage: "The stardard prefix used to denote release branches",
		Value: "release",
	}

	DevTagSuffixFlagName = "dev-tag-suffix"
	DevTagSuffixFlag     = &cli.StringFlag{
		Name:    "dev-tag-suffix",
		Usage:   "The suffix used to denote development tags",
		EnvVars: []string{"DEV_TAG_SUFFIX"},
		Value:   "0.dev",
	}
)

var (
	SkipValidationFlagName = "skip-validation"
	SkipValidationFlag     = &cli.BoolFlag{
		Name:  "skip-validation",
		Usage: "Skip all validation while performing the action",
		Value: false,
	}
)

var (
	RegistryFlagName = "registry"
	RegistryFlag     = &cli.StringSliceFlag{
		Name:    RegistryFlagName,
		Usage:   "Override default registries for the release. Repeat for multiple registries.",
		EnvVars: []string{"REGISTRIES"},
		Value:   cli.NewStringSlice(),
	}
)

var (
	ArchFlagName = "arch"
	ArchFlag     = &cli.StringSliceFlag{
		Name:    ArchFlagName,
		Usage:   "The architecture to use for the release. Repeat for multiple architectures.",
		EnvVars: []string{"ARCHES"},
		Value:   cli.NewStringSlice("amd64", "arm64", "ppc64le", "s390x"),
	}
)

var BuildImagesFlagName = "build-images"

func BuildImagesFlag(defaultValue bool, product string) *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:    BuildImagesFlagName,
		Usage:   fmt.Sprintf("Build container images for %s from local codebase", product),
		EnvVars: []string{"BUILD_CONTAINER_IMAGES"},
		Value:   defaultValue,
	}
}

var PublishImagesFlagName = "publish-images"

func PublishImagesFlag(defaultValue bool) *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:    PublishImagesFlagName,
		Usage:   "Publish images to the registry",
		EnvVars: []string{"PUBLISH_IMAGES"},
		Value:   defaultValue,
	}
}

var (
	GitHubTokenFlagName = "github-token"
	GitHubTokenFlag     = &cli.StringFlag{
		Name:    "github-token",
		Usage:   "The GitHub token to use when interacting with the GitHub API",
		EnvVars: []string{"GITHUB_TOKEN"},
	}
)
