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

// Package setup resolves the release defaults the operator publishes with.
//
// It is a separate package so it initializes before the release tool's flag defaults
// (hack/release/flags.go), which capture these values by value and so need them resolved first.
package setup

import (
	"fmt"
	"regexp"
)

const (
	quayRegistry         = "quay.io"
	operatorImage        = "tigera/operator"
	releaseVersionFormat = `^v\d+\.\d+\.\d+$`
)

var (
	DefaultRegistry = quayRegistry
	DefaultImage    = operatorImage

	// IsValidReleaseVersion validates the operator release version.
	IsValidReleaseVersion = matchesFormat(releaseVersionFormat)

	// IsValidCalicoReleaseVersion validates a Calico release version.
	IsValidCalicoReleaseVersion = matchesFormat(releaseVersionFormat)

	CreateGitHubReleaseDefault = true
)

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
