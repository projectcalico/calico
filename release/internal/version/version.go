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
)

// Versions is the interface that provides version data for a hashrelease or release.
type Versions interface {
	Hash() string
	ProductVersion() string
	OperatorVersion() string
	HelmChartVersion() string
	ReleaseBranch(releaseBranchPrefix string) string
}

func NewHashreleaseVersions(calico Version, operator string) Versions {
	return &HashreleaseVersions{
		calico:   calico,
		operator: operator,
	}
}

// HashreleaseVersions implements the Versions interface for a hashrelease.
type HashreleaseVersions struct {
	calico   Version
	operator string
}

func (v *HashreleaseVersions) ProductVersion() string {
	return v.calico.FormattedString()
}

func (v *HashreleaseVersions) OperatorVersion() string {
	return fmt.Sprintf("%s-%s", v.operator, v.ProductVersion())
}

func (v *HashreleaseVersions) HelmChartVersion() string {
	return v.calico.FormattedString()
}

func (v *HashreleaseVersions) Hash() string {
	return fmt.Sprintf("%s-%s", v.calico.FormattedString(), v.operator)
}

func (v *HashreleaseVersions) ReleaseBranch(releaseBranchPrefix string) string {
	return fmt.Sprintf("%s-%s", releaseBranchPrefix, v.calico.Stream())
}

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
func (v *Version) Milestone(prefix string) string {
	if prefix == "" {
		prefix = utils.ProductName
	}
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("%s v%d.%d.%d", prefix, ver.Major(), ver.Minor(), ver.Patch())
}

// Stream returns the "release stream" of the version.
// Typically it is the major and minor version without the patch version.
// For example, for version "v3.15.0", the stream is "v3.15".
//
// Early preview versions are handled differently.
// For example, for version "v3.15.0-1.0", the stream is "v3.15-1".
// For version "v3.15.0-2.0", the stream is "v3.15" (same as v3.15.1+).
func (v *Version) Stream() string {
	ver := v.Semver()
	ep, epVer := IsEarlyPreviewVersion(ver)
	stream := fmt.Sprintf("v%d.%d", ver.Major(), ver.Minor())
	if ep && epVer == 1 {
		return fmt.Sprintf("%s-1", v.String())
	}
	return stream
}

func (v *Version) Semver() *semver.Version {
	ver := semver.MustParse(string(*v))
	return ver
}

// NextBranchVersion returns version of the next branch.
// If the version is a EP1 version, then return EP2.
// Otherwise, increment the minor version.
func (v *Version) NextBranchVersion() Version {
	ver := v.Semver()
	ep, epVer := IsEarlyPreviewVersion(ver)
	if ep && epVer == 1 {
		return New(fmt.Sprintf("v%d.%d.0-2.0", ver.Major(), ver.Minor()))
	}
	return New(ver.IncMinor().String())
}

// IsEarlyPreviewVersion handles the logic for determining if a version is an early preview (EP) version.
//
// An early preview version is a version that has a prerelease tag starting with "1." or "2.".
// The function returns true if it is an EP and EP major version as EP 1 is treated differently from EP 2.
func IsEarlyPreviewVersion(v *semver.Version) (bool, int) {
	if v.Prerelease() != "" {
		if strings.HasPrefix(v.Prerelease(), "1.") {
			return true, 1
		} else if strings.HasPrefix(v.Prerelease(), "2.") {
			return true, 2
		}
	}
	return false, -1
}

// GitVersion returns the current git version of the directory as a Version object.
func GitVersion() Version {
	// First, determine the git revision.
	previousTag, err := command.GitVersion(".", true)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to determine latest git version")
	}
	logrus.WithField("out", previousTag).Info("Current git describe")
	return New(previousTag)
}

// HasDevTag returns true if the version has the given dev tag suffix.
// The dev tag suffix is expected to be in one of the following formats:
//   - vX.Y.Z-<devTagSuffix>-N-gCOMMIT
//   - vX.Y.Z-<devTagSuffix>-N-gCOMMIT-dirty
//   - vX.Y.Z-A.B-<devTagSuffix>-N-gCOMMIT
//   - vX.Y.Z-A.B-<devTagSuffix>-N-gCOMMIT-dirty
//
// where vX.Y.Z is the semver version, <devTagSuffix> is the dev tag suffix, N is the number of commits since the tag,
// A.B is the EP version, and COMMIT is the git commit hash abbreviated to 12 characters (e.g., 1a2b3c4d5e67).
// The "dirty" suffix indicates that the working directory is dirty.
func HasDevTag(v Version, devTagSuffix string) bool {
	devTagSuffix = strings.TrimPrefix(devTagSuffix, "-")
	re := regexp.MustCompile(fmt.Sprintf(`^v\d+\.\d+\.\d+(-\d+\.\d+)?-%s-\d+-g[0-9a-f]{12}(-dirty)?$`, devTagSuffix))
	return re.MatchString(string(v))
}

// DetermineReleaseVersion uses historical clues to figure out the next semver
// release number to use for this release based on the current git revision.
//   - If the current git revision is a "vX.Y.Z-<devTagSuffix>-N-gCOMMIT" tag, then the next release version is simply vX.Y.Z.
//   - If the current git revision is a patch release with no dev tag (e.g., vX.Y.Z-N-gCOMMIT), then the next release version is vX.Y.Z+1.
//   - If the current git revision is a patch release with a dev tag (e.g., vX.Y.Z-<devTagSuffix>-N-gCOMMIT), then the next release version is vX.Y.Z.
func DetermineReleaseVersion(v Version, devTagSuffix string) (Version, error) {
	gitVersion := v.FormattedString()

	// There are two types of tag that this might be - either it was a previous patch release,
	// or it was a "vX.Y.Z-<devTagSuffix>" tag produced when cutting the release branch.
	if HasDevTag(v, devTagSuffix) {
		// This is the first release from this branch - we can simply extract the version from
		// the dev tag.
		if !strings.HasPrefix(devTagSuffix, "-") {
			// The dev tag marker should start with a hyphen.
			// For example in "v3.15.0-0.dev-1-g1a2b3c4d5e67" with devTagSuffix "0.dev",
			// we want to split on the "-0.dev" part and return "v3.15.0".
			devTagSuffix = "-" + devTagSuffix
		}
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

// DeterminePublishStream returns the stream for a given branch and version.
// If the branch is the default branch i.e. master, the stream is master.
// Otherwise, the stream is the major and minor version of the version.
func DeterminePublishStream(branch string, version string) string {
	if branch == utils.DefaultBranch {
		return branch
	}
	ver := New(version)
	return ver.Stream()
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
