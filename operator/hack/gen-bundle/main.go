// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// gen-bundle stages the manifests that 'operator-sdk generate bundle' reads and
// applies the build-time values to the bundle it generates.
//
// It is not meant to be run directly. See the bundle target in the Makefile.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "gen-bundle",
		Usage: "Build an operator bundle that can be certified",
		Commands: []*cli.Command{
			getManifestsCommand,
			updateBundleCommand,
		},
		Flags: []cli.Flag{debugFlag},
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			if c.Bool(debugFlag.Name) {
				logrus.SetLevel(logrus.DebugLevel)
			}
			return ctx, nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running command")
	}
}

var debugFlag = &cli.BoolFlag{
	Name:    "debug",
	Usage:   "Enable debug logging",
	Sources: cli.EnvVars("DEBUG"),
}

// repoRootFlag anchors the manifests and CRDs that the bundle ships, so that
// staging them does not depend on where gen-bundle was run from. The Makefile
// passes the root that git reported; the default covers running it by hand from
// the operator directory.
var repoRootFlag = &cli.StringFlag{
	Name:      "repo-root",
	Usage:     "Root of the Calico repository to stage the manifests and CRDs from",
	Sources:   cli.EnvVars("REPO_ROOT"),
	Value:     "..",
	Validator: nonEmpty("repo-root"),
}

// Staging directory flags. These name the directories that
// 'operator-sdk generate bundle' is pointed at.
var (
	crdDirFlag = &cli.StringFlag{
		Name:      "crd-dir",
		Usage:     "Directory to stage the CRDs the bundle ships in",
		Sources:   cli.EnvVars("BUNDLE_CRD_DIR"),
		Required:  true,
		Validator: nonEmpty("crd-dir"),
	}
	deployDirFlag = &cli.StringFlag{
		Name:      "deploy-dir",
		Usage:     "Directory to stage the operator manifests and sample CRs in",
		Sources:   cli.EnvVars("BUNDLE_DEPLOY_DIR"),
		Required:  true,
		Validator: nonEmpty("deploy-dir"),
	}
)

// Release flags.
var (
	versionFlag = &cli.StringFlag{
		Name:      "version",
		Usage:     "The version of the operator to publish, as X.Y.Z",
		Sources:   cli.EnvVars("VERSION"),
		Required:  true,
		Validator: nonEmpty("version"),
	}
	prevVersionFlag = &cli.StringFlag{
		Name:      "prev-version",
		Usage:     "The version of the operator that this version replaces, as X.Y.Z. Use 0.0.0 if it replaces nothing",
		Sources:   cli.EnvVars("PREV_VERSION"),
		Required:  true,
		Validator: nonEmpty("prev-version"),
	}
	// The capabilities level is the claim the bundle is certified against, so it
	// is only raised deliberately - hence the flag rather than a value in the CSV
	// base, which would be easy to change without noticing what it asserts.
	capabilitiesFlag = &cli.StringFlag{
		Name:      "capabilities",
		Usage:     "The Operator Capability Level the bundle claims, e.g. 'Basic Install' or 'Seamless Upgrades'",
		Sources:   cli.EnvVars("BUNDLE_CAPABILITIES"),
		Value:     "Basic Install",
		Validator: nonEmpty("capabilities"),
	}
)

// Image flags. update-bundle pulls and inspects the operator image itself; the
// inspection overrides bypass the pull, for running it by hand against an image
// that is not in a registry we can reach.
var (
	imageFlag = &cli.StringFlag{
		Name:      "image",
		Usage:     "The operator image repository the bundle pins its digest from. The tag comes from --version",
		Sources:   cli.EnvVars("OPERATOR_IMAGE"),
		Value:     "quay.io/calico/operator",
		Validator: nonEmpty("image"),
	}
	imageInspectFlag = &cli.StringFlag{
		Name:    "image-inspect",
		Usage:   "Output of 'docker image inspect' for the operator image, raw or base64-encoded, instead of running it",
		Sources: cli.EnvVars("OPERATOR_IMAGE_INSPECT"),
	}
	manifestInspectFlag = &cli.StringFlag{
		Name:    "manifest-inspect",
		Usage:   "Output of 'docker manifest inspect' for the operator image, raw or base64-encoded, instead of running it",
		Sources: cli.EnvVars("OPERATOR_MANIFEST_INSPECT"),
	}
)

// nonEmpty returns a flag validator that rejects an empty value, naming the
// flag so that the failure points at the variable the Makefile did not set.
func nonEmpty(name string) func(string) error {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is empty", name)
		}
		return nil
	}
}
