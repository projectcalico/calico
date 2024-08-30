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
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/builder"
)

// Version represents a version, and contains methods for working with versions.
type Version string

// New creates a new Version object from the given string.
func New(version string) Version {
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
	branch := fmt.Sprintf("%s-%s", releaseBranchPrefix, v.Stream())
	prerelese := semver.MustParse(string(*v)).Prerelease()
	if prerelese != "" {
		if strings.HasPrefix(prerelese, "1.") {
			branch += "-1"
		}
	}
	return branch
}

// NextVersion returns the next minor version that follows this version.
// To determine the next version to release, instead use DetermineReleaseVersion.
func (v *Version) NextVersion() Version {
	ver := semver.MustParse(string(*v))
	if ver.Prerelease() != "" && strings.HasPrefix(ver.Prerelease(), "1.") {
		prerelease := semver.MustParse(ver.Prerelease())
		nextPrerelease := prerelease.IncMajor()
		vNextPrerelease := fmt.Sprintf("%v.%v", nextPrerelease.Major(), nextPrerelease.Minor())
		vNext := semver.New(ver.Major(), ver.Minor(), ver.Patch(), vNextPrerelease, "")
		return Version(vNext.String())
	}
	return Version(ver.IncMinor().String())
}

// IsDevVersion returns true if the version includes the dev marker.
// The dev marker can be used in a tag to indicate what the next release version will be. If present,
// it means the version is of the form vX.Y.Z-<devTag>-<commitsSinceTag>-g<commitHash>, where vX.Y.Z
// is the _next_ (currently unreleased) product version.
func IsDevVersion(ver, devTag string) bool {
	v := Version(ver)
	pattern := fmt.Sprintf(`^v\d+\.\d+\.\d+(-\d+\.\d+)?-%s-\d+-g[0-9a-f]{12}(-dirty)?$`, devTag)
	re := regexp.MustCompile(pattern)
	return re.MatchString(v.FormattedString())
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
func DetermineReleaseVersion(v Version) (Version, error) {
	gitVersion := v.FormattedString()

	// There are two types of tag that this might be - either it was a previous patch release,
	// or it was a "vX.Y.Z-0.dev" tag produced when cutting the release branch.
	if strings.Contains(gitVersion, "-0.dev") {
		// This is the first release from this branch - we can simply extract the version from
		// the dev tag.
		return New(strings.Split(gitVersion, "-0.dev")[0]), nil
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
	runner := &builder.RealCommandRunner{}
	manifests := []string{"tigera-operator.yaml"}
	var operatorVersion string
	for _, m := range manifests {
		args := []string{"-Po", `image:\K(.*)`, m}
		out, err := runner.RunInDir(filepath.Join(repoRoot, "manifests"), "grep", args, nil)
		if err != nil {
			panic(err)
		}

		imgs := strings.Split(out, "\n")

		for _, i := range imgs {
			if strings.Contains(i, "operator") && operatorVersion == "" {
				splits := strings.SplitAfter(i, ":")
				operatorVersion = splits[len(splits)-1]
			}
		}
		if operatorVersion != "" {
			break
		}
	}

	if operatorVersion == "" {
		panic("Missing version!")
	}

	return New(operatorVersion), nil
}
