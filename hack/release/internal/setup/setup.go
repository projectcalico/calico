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

// Package setup resolves everything that differs between the regular Calico/Enterprise release and
// the Calico Cloud release — the publish registry/image, the release-version format, and the
// GitHub-release default — once, at package-init time, keyed off the VARIANT env var. This is what
// makes one release binary serve both flows (per PR review from @radTuti / @caseydavenport): the
// difference is options resolved at runtime, not a separate build.
//
// It is a separate package purely for initialization ordering. Go fully initializes an imported
// package — its variables AND its init() — before the importing package initializes its own
// variables. The release tool's flag defaults (hack/release/flags.go) are package-level vars that
// capture these values by value, so resolving the variant here means those flag defaults capture the
// correct cloud/enterprise values directly, with no later fix-up in the main package.
package setup

import (
	"fmt"
	"os"
	"regexp"
)

const (
	quayRegistry    = "quay.io"
	enterpriseImage = "tigera/operator"

	gcrRegistry = "gcr.io"
	cloudImage  = "tigera-tesla/operator-cloud"

	// releaseVersionFormat is the regular operator release format (vX.Y.Z). Cloud releases use the
	// same scheme with a -cloud suffix (e.g. v1.44.0-cloud). The enterprise format is duplicated
	// from hack/release/utils.go's releaseFormat because package main cannot be imported; keep them
	// in sync.
	releaseVersionFormat      = `^v\d+\.\d+\.\d+$`
	cloudReleaseVersionFormat = `^v\d+\.\d+\.\d+-cloud$`
)

// IsCloud reports whether the release tool is running as the Calico Cloud variant. It is driven by
// the VARIANT env var (set by `make ... VARIANT=cloud`). Resolved once, at package init.
var IsCloud = os.Getenv("VARIANT") == "cloud"

// Variant-dependent defaults. They start as the enterprise values and are switched to the cloud
// values by init() when IsCloud is true.
var (
	// DefaultRegistry and DefaultImage are the publish defaults for the operator image.
	DefaultRegistry = quayRegistry
	DefaultImage    = enterpriseImage

	// IsValidReleaseVersion validates a release version string for the active variant.
	IsValidReleaseVersion = matchesFormat(releaseVersionFormat)

	// CreateGitHubReleaseDefault is the default for the --create-github-release flag. Cloud releases
	// are not published on GitHub, so cloud defaults it off.
	CreateGitHubReleaseDefault = true
)

func init() {
	if !IsCloud {
		return
	}
	DefaultRegistry = gcrRegistry
	DefaultImage = cloudImage
	IsValidReleaseVersion = matchesFormat(cloudReleaseVersionFormat)
	CreateGitHubReleaseDefault = false
}

// matchesFormat returns a validator reporting whether a version matches the given regex.
func matchesFormat(format string) func(string) (bool, error) {
	return func(version string) (bool, error) {
		re, err := regexp.Compile(format)
		if err != nil {
			return false, fmt.Errorf("compiling release regex: %w", err)
		}
		return re.MatchString(version), nil
	}
}
