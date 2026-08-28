// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"fmt"
	"regexp"

	gv "github.com/hashicorp/go-version"
	"github.com/tigera/operator/version"
)

var (
	buildVersion            *gv.Version
	gitDescribeSuffixRegexp = regexp.MustCompile(`-\d+-\w+$`)
	versionRegexp           = regexp.MustCompile("^" + gv.VersionRegexpRaw + "$")
)

func init() {
	bv, err := versionFromBuildVersion(version.VERSION)
	if err != nil {
		log.Info(err.Error())
		return
	}

	buildVersion = bv
}

// checkOperatorVersion validates that the current operator version (the build version) meets
// the minimum required version specified by the CRD. If the build version is not a valid version,
// checks are ignored.
func checkOperatorVersion(minRequiredVersion string) error {
	if minRequiredVersion == "" {
		return nil
	}

	// If we don't have a version skip version checking.
	if buildVersion == nil {
		log.Info("No valid build version, skipping operator version checks")
		return nil
	}

	minVersion, err := gv.NewVersion(minRequiredVersion)
	if err != nil {
		return fmt.Errorf("invalid version specified: %s", err.Error())
	}

	if buildVersion.GreaterThanOrEqual(minVersion) {
		return nil
	}

	return fmt.Errorf("specified operator version does not meet minimum requirement")
}

// versionFromBuildVersion takes a build version string and converts it to a version.Version.
// The build version string is automatically set to 'git describe' output during the build process.
func versionFromBuildVersion(buildVersion string) (*gv.Version, error) {
	// Make sure the build version is a valid version.
	matches := versionRegexp.FindStringSubmatch(buildVersion)
	if matches == nil {
		return nil, fmt.Errorf("invalid build version: %q", buildVersion)
	}

	s := gitDescribeSuffixRegexp.ReplaceAllString(buildVersion, "")
	return gv.NewVersion(s)
}
