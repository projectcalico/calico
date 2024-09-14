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

package version

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

// Version represents a version, and contains methods for working with versions.
type Version string

// New creates a new Version object from the given string.
func New(version string) Version {
	if _, err := semver.NewVersion(strings.TrimPrefix(version, "v")); err != nil {
		logrus.WithField("version", version).WithError(err).Fatal("Failed to parse version")
	}
	return Version(version)
}

// String returns the string representation of the version.
func (v *Version) String() string {
	ver, err := semver.NewVersion(strings.TrimPrefix(string(*v), "v"))
	if err != nil {
		return ""
	}
	return ver.String()
}

// FormattedString returns the formatted string representation of the version.
func (v *Version) FormattedString() string {
	return fmt.Sprintf("v%v", v.String())
}

// Milestone returns the GitHub milestone name which corresponds with this version.
func (v *Version) Milestone() string {
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("%s v%d.%d.%d", utils.DisplayProductName(), ver.Major(), ver.Minor(), ver.Patch())
}

// Stream returns the "release stream" of the version, i.e., the major and minor version without the patch version.
func (v *Version) Stream() string {
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("v%d.%d", ver.Major(), ver.Minor())
}

// ReleaseBranch returns the release branch which corresponds with this version.
func (v *Version) ReleaseBranch(releaseBranchPrefix string) string {
	return fmt.Sprintf("%s-%s", releaseBranchPrefix, v.Stream())
}

// GitVersion returns the current git version of the repository as a Version object.
func GitVersion() Version {
	// First, determine the git revision.
	previousTag, err := command.GitVersion(".", true)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to determine latest git version")
	}
	logrus.WithField("out", previousTag).Info("Current git describe")
	return New(previousTag)
}

// DetermineReleaseVersion uses historical clues to figure out the next semver
// release number to use for this release based on the current git revision.
//
// OSS Calico uses the following rules:
// - If the current git revision is a "vX.Y.Z-0.dev-N-gCOMMIT" tag, then the next release version is simply vX.Y.Z.
// - If the current git revision is a patch release (e.g., vX.Y.Z-N-gCOMMIT), then the next release version is vX.Y.Z+1.
func DetermineReleaseVersion(v Version, devTagSuffix string) (Version, error) {
	gitVersion := v.FormattedString()

	if !strings.HasPrefix(devTagSuffix, "-") {
		// The dev tag marker should start with a hyphen.
		// For example in "v3.15.0-0.dev-1-g1234567", we want to split on the "-0.dev" part.
		devTagSuffix = "-" + devTagSuffix
	}

	// There are two types of tag that this might be - either it was a previous patch release,
	// or it was a "vX.Y.Z-0.dev" tag produced when cutting the release branch.
	if strings.Contains(gitVersion, devTagSuffix) {
		// This is the first release from this branch - we can simply extract the version from
		// the dev tag.
		return New(strings.Split(gitVersion, devTagSuffix)[0]), nil
	} else {
		// This is a patch release - we need to parse the previous, and
		// bump the patch version.
		previousVersion := strings.Split(gitVersion, "-")[0]
		logrus.WithField("previousVersion", previousVersion).Info("Previous version")
		v, err := semver.NewVersion(strings.TrimPrefix(previousVersion, "v"))
		if err != nil {
			logrus.WithField("previousVersion", previousVersion).WithError(err).Error("Failed to parse git version as semver")
			return "", fmt.Errorf("failed to parse git version as semver: %s", err)
		}
		newVersion := v.IncPatch()
		return New(fmt.Sprintf("v%s", newVersion.String())), nil
	}
}

// DetermineOperatorVersion returns the operator version that will be used for this release.
// This is determined by looking at the tigera-operator.yaml manifest on this commit, as
// manifests are updated prior to cutting the release.
func DetermineOperatorVersion(repoRoot string) (Version, error) {
	return versionFromManifest(repoRoot, "tigera-operator.yaml", "operator")
}

// VersionsFromManifests returns the versions of the product and operator from manifests.
func VersionsFromManifests(repoRoot string) (Version, Version, error) {
	productVersion, err := versionFromManifest(repoRoot, "ocp/02-tigera-operator.yaml", "ctl")
	if err != nil {
		return "", "", err
	}
	operatorVersion, err := versionFromManifest(repoRoot, "tigera-operator.yaml", "operator")
	if err != nil {
		return "", "", err
	}
	return productVersion, operatorVersion, nil
}

// versionFromManifest returns the version of the image matching the given match string from the given manifest.
func versionFromManifest(repoRoot, manifest, imgMatch string) (Version, error) {
	runner := &command.RealCommandRunner{}
	args := []string{"-Po", `image:\K(.*)`, manifest}
	out, err := runner.RunInDir(filepath.Join(repoRoot, "manifests"), "grep", args, nil)
	if err != nil {
		return "", fmt.Errorf("failed to grep for image in manifest %s: %s", manifest, err)
	}

	imgs := strings.Split(out, "\n")
	for _, i := range imgs {
		if strings.Contains(i, imgMatch) {
			splits := strings.SplitAfter(i, ":")
			ver := splits[len(splits)-1]
			return New(ver), nil
		}
	}
	return "", fmt.Errorf("image for %s not found in manifest %s", imgMatch, manifest)
}
