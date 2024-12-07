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

import cli "github.com/urfave/cli/v2"

const (
	latestFlag          = "latest"
	skipValidationFlag  = "skip-validation"
	skipImageScanFlag   = "skip-image-scan"
	skipBranchCheckFlag = "skip-branch-check"
	publishBranchFlag   = "git-publish"
	buildImagesFlag     = "build-images"

	orgFlag  = "org"
	repoFlag = "repo"

	imageRegistryFlag = "registry"

	operatorOrgFlag      = "operator-org"
	operatorRepoFlag     = "operator-repo"
	operatorImageFlag    = "operator-image"
	operatorRegistryFlag = "operator-registry"

	sourceBranchFlag = "source-branch"
	newBranchFlag    = "new-branch-version"

	// Configuration flags for the release publish command.
	skipPublishImagesFlag        = "skip-publish-images"
	skipPublishGitTagFlag        = "skip-publish-git-tag"
	skipPublishGithubReleaseFlag = "skip-publish-github-release"
	skipPublishHashreleaseFlag   = "skip-publish-hashrelease-server"
)

// globalFlags are flags that are available to all sub-commands.
var globalFlags = []cli.Flag{
	&cli.BoolFlag{
		Name:        "debug",
		Aliases:     []string{"d"},
		Usage:       "Enable verbose log output",
		Value:       false,
		Destination: &debug,
	},
}
