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

// Package setup resolves the release defaults that differ between the Calico/Enterprise and Calico
// Cloud variants (publish registry/image, release-version format, GitHub-release default) at init
// time, keyed off the VARIANT env var.
//
// It is a separate package so it initializes before the release tool's flag defaults
// (hack/release/flags.go), which capture these values by value and so need them resolved first.
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

	releaseVersionFormat      = `^v\d+\.\d+\.\d+$`
	cloudReleaseVersionFormat = `^v\d+\.\d+\.\d+-cloud$`
)

// IsCloud reports whether the release tool is running as the Calico Cloud variant.
var IsCloud = os.Getenv("VARIANT") == "cloud"

// Variant-dependent defaults, set to the enterprise values here and switched to cloud by init().
var (
	DefaultRegistry = quayRegistry
	DefaultImage    = enterpriseImage

	// IsValidReleaseVersion validates the operator release version for the active variant (plain
	// vX.Y.Z for enterprise, vX.Y.Z-cloud for cloud).
	IsValidReleaseVersion = matchesFormat(releaseVersionFormat)

	// IsValidCalicoReleaseVersion validates a Calico release version. It stays plain vX.Y.Z for all
	// variants: the Calico version never carries the -cloud suffix.
	IsValidCalicoReleaseVersion = matchesFormat(releaseVersionFormat)

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
