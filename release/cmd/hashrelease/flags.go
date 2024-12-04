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

import "github.com/urfave/cli/v2"

// Validation flags
var (
	skipBranchCheckFlagName = "skip-branch-check"
	skipBranchCheckFlag     = &cli.BoolFlag{
		Name:  "skip-branch-check",
		Usage: "Skip checking if current branch is a valid branch for release",
		Value: false,
	}

	skipImageScanFlagName = "skip-image-scan"
	skipImageScanFlag     = &cli.BoolFlag{
		Name:  "skip-image-scan",
		Usage: "Skip sending the image to the image scan service",
	}
)

// Image Scanner flags
var (
	imageScannerAPIFlagName = "image-scanner-api"
	imageScannerAPIFlag     = &cli.StringFlag{
		Name:    "image-scanner-api",
		Usage:   "The URL for the Image Scan Service API",
		EnvVars: []string{"IMAGE_SCANNER_API"},
	}

	imageScannerTokenFlagName = "image-scanning-token"
	imageScannerTokenFlag     = &cli.StringFlag{
		Name:    "image-scanner-token",
		Usage:   "The token for the Image Scan Service API",
		EnvVars: []string{"IMAGE_SCANNING_TOKEN"},
	}

	imageScannerSelectFlagName = "image-scanner-select"
	imageScannerSelectFlag     = &cli.StringFlag{
		Name:    "image-scanner-select",
		Usage:   "The name of the scanner to use",
		EnvVars: []string{"IMAGE_SCANNER_SELECT"},
		Value:   "all",
	}

	imageScannerFlags = []cli.Flag{skipImageScanFlag, imageScannerAPIFlag, imageScannerTokenFlag, imageScannerSelectFlag}
)

// Publishing flags
var (
	sshHostFlagName = "host"
	sshHostFlag     = &cli.StringFlag{
		Name:    "host",
		Aliases: []string{"H"},
		Usage:   "The SSH host for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_HOST"},
	}

	sshUserFlagName = "user"
	sshUserFlag     = &cli.StringFlag{
		Name:    "user",
		Aliases: []string{"U"},
		Usage:   "The SSH user for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_USER"},
	}

	sshKeyFlagName = "key"
	sshKeyFlag     = &cli.StringFlag{
		Name:    "key",
		Aliases: []string{"K"},
		Usage:   "The SSH key for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_KEY"},
	}

	sshPortFlagName = "port"
	sshPortFlag     = &cli.StringFlag{
		Name:    "port",
		Aliases: []string{"P"},
		Usage:   "The SSH port for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_PORT"},
	}

	sshKnownHostsFlagName = "known-hosts"
	sshKnownHostsFlag     = &cli.StringFlag{
		Name:    "known-hosts",
		Aliases: []string{"KH"},
		Usage:   "The known_hosts file to use for the connection to the hashrelease server",
		EnvVars: []string{"DOCS_KNOWN_HOSTS"},
	}

	publishHashreleaseFlagName = "publish-to-hashrelease-server"
	publishHashreleaseFlag     = &cli.BoolFlag{
		Name:    "publish-to-hashrelease-server",
		Aliases: []string{"phr"},
		Usage:   "Publish the hashrelease to the hashrelease server",
		Value:   true,
	}

	latestFlagName = "latest"
	latestFlag     = &cli.BoolFlag{
		Name:  "latest",
		Usage: "Publish the hashrelease as the latest hashrelease",
		Value: true,
	}
)
