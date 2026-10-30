// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/defaults"
)

// Version is a parsed semver version. Build one with New; the zero value is
// only good for String, which returns "".
type Version struct {
	sv *semver.Version
}

// New parses version, with or without a leading "v".
func New(version string) (Version, error) {
	sv, err := semver.NewVersion(strings.TrimPrefix(version, "v"))
	if err != nil {
		return Version{}, fmt.Errorf("parse version %q: %w", version, err)
	}
	return Version{sv: sv}, nil
}

func fromSemver(sv semver.Version) Version {
	return Version{sv: &sv}
}

// String returns the version with a leading "v", whether or not New got one.
func (v Version) String() string {
	if v.sv == nil {
		return ""
	}
	return "v" + v.sv.String()
}

// Milestone returns the GitHub milestone name which corresponds with this version.
func (v Version) Milestone(prefix string) string {
	if prefix == "" {
		prefix = defaults.ProductName
	}
	return fmt.Sprintf("%s v%d.%d.%d", prefix, v.sv.Major(), v.sv.Minor(), v.sv.Patch())
}

// Stream returns the "release stream" of the version.
// Typically it is the major and minor version without the patch version.
// For example, for version "v3.15.0", the stream is "v3.15".
//
// Early preview versions are handled differently.
// For example, for version "v3.15.0-1.0", the stream is "v3.15-1".
// For version "v3.15.0-2.0", the stream is "v3.15" (same as v3.15.1+).
func (v Version) Stream() string {
	ver := v.Semver()
	ep, epVer := IsEarlyPreviewVersion(ver)
	stream := fmt.Sprintf("v%d.%d", ver.Major(), ver.Minor())
	if ep && epVer == 1 {
		return fmt.Sprintf("%s-1", stream)
	}
	return stream
}

// PrimaryStream returns the stream without any EP suffix.
func (v Version) PrimaryStream() string {
	return strings.Split(v.Stream(), "-")[0]
}

func (v Version) Semver() *semver.Version {
	return v.sv
}

// NextBranchVersion returns version of the next branch.
// If the version is a EP1 version, then return EP2.
// Otherwise, increment the minor version.
func (v Version) NextBranchVersion() Version {
	ver := v.Semver()
	ep, epVer := IsEarlyPreviewVersion(ver)
	if ep {
		if epVer == 1 {
			return fromSemver(*semver.New(ver.Major(), ver.Minor(), 0, "2.0", ""))
		}
		return fromSemver(*semver.New(ver.Major(), ver.Minor()+1, 0, "1.0", ""))
	}
	return fromSemver(ver.IncMinor())
}

var epIsEarlyPreview = func(v *semver.Version) (bool, int) {
	if v.Prerelease() == "" {
		return false, -1
	}
	if strings.HasPrefix(v.Prerelease(), "1.") {
		return true, 1
	} else if strings.HasPrefix(v.Prerelease(), "2.") {
		return true, 2
	}
	return false, -1
}

// IsEarlyPreviewVersion reports whether v is an early-preview version and, if
// so, its EP line. GA and non-EP versions return (false, -1).
func IsEarlyPreviewVersion(v *semver.Version) (bool, int) {
	return epIsEarlyPreview(v)
}

// NextReleaseVersion returns the next version for a release in the current branch.
// If the version is a EP1 version, it will increment the EP version.
// If the version is a EP2 version, it will increment to GA version.
// If the version is a GA version, it will increment the patch version.
//
// For example, for version "v3.15.0-1.0", the next release version is "v3.15.0-1.1".
// For version "v3.15.0-2.0", the next release version is "v3.15.1".
// For version "v3.15.0", the next release version is "v3.15.1".
// For version "v3.15.0-1.0-1-g1a2b3c4d5e67", the next release version is "v3.15.0-1.1".
func (v Version) NextReleaseVersion() (Version, error) {
	ver := v.Semver()
	ep, epVer := IsEarlyPreviewVersion(ver)
	if ep {
		if epVer == 1 {
			// EP 1 = increment EP version i.e vX.Y.Z-1.0 to vX.Y.Z-1.1
			parts := strings.Split(ver.Prerelease(), ".")
			minorEPver, err := strconv.Atoi(strings.Split(parts[1], "-")[0])
			if err != nil {
				return Version{}, fmt.Errorf("parse minor EP version of %s: %w", v, err)
			}
			return fromSemver(*semver.New(ver.Major(), ver.Minor(), 0, fmt.Sprintf("1.%d", minorEPver+1), "")), nil
		}
		// EP 2 - increment to GA version i.e vX.Y.Z-2.0 to vX.Y.1
		return fromSemver(*semver.New(ver.Major(), ver.Minor(), 1, "", "")), nil
	}
	// GA versions - increment patch version i.e vX.Y.Z to vX.Y.Z+1
	return fromSemver(ver.IncPatch()), nil
}

// GitVersion returns the current git version of the directory as a Version object.
func GitVersion() (Version, error) {
	previousTag, err := command.GitVersion(".", true)
	if err != nil {
		return Version{}, fmt.Errorf("determine git version: %w", err)
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
	return re.MatchString(v.String())
}

// DetermineReleaseVersion uses historical clues to figure out the next semver
// release number to use for this release based on the current git revision.
//   - If the current git revision is a "vX.Y.Z-<devTagSuffix>-N-gCOMMIT" tag, then the next release version is simply vX.Y.Z.
//   - If the current git revision is a patch release with no dev tag (e.g., vX.Y.Z-N-gCOMMIT), then the next release version is vX.Y.Z+1.
//   - If the current git revision is a patch release with a dev tag (e.g., vX.Y.Z-<devTagSuffix>-N-gCOMMIT), then the next release version is vX.Y.Z.
func DetermineReleaseVersion(v Version, devTagSuffix string) (Version, error) {
	gitVersion := v.String()

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
		return New(strings.Split(gitVersion, devTagSuffix)[0])
	} else {
		// This is a patch release - we need to parse the previous, and
		// bump the patch version.
		previousVersion := strings.Split(gitVersion, "-")[0]
		logrus.WithField("previousVersion", previousVersion).Info("Previous version")
		v, err := semver.NewVersion(strings.TrimPrefix(previousVersion, "v"))
		if err != nil {
			logrus.WithField("previousVersion", previousVersion).WithError(err).Error("Failed to parse git version as semver")
			return Version{}, fmt.Errorf("failed to parse git version as semver: %w", err)
		}
		return fromSemver(v.IncPatch()), nil
	}
}

type ReleaseBranch struct {
	prefix string
	Stream string
}

var (
	streamRe = regexp.MustCompile(`^v\d+\.\d+([.-].*)?$`)
	epLineRe = regexp.MustCompile(`^v\d+\.\d+-(\d+)$`)
)

func NewReleaseBranch(prefix string, v Version) ReleaseBranch {
	return ReleaseBranch{prefix: prefix, Stream: v.Stream()}
}

// ParseReleaseBranch returns false for the default branch and any branch that is not
// "<prefix>-vX.Y...".
func ParseReleaseBranch(prefix, branch string) (ReleaseBranch, bool) {
	stream, ok := strings.CutPrefix(branch, prefix+"-")
	if !ok || !streamRe.MatchString(stream) {
		return ReleaseBranch{}, false
	}
	return ReleaseBranch{prefix: prefix, Stream: stream}, true
}

func (b ReleaseBranch) String() string {
	return b.prefix + "-" + b.Stream
}

// EPLine returns N for a "vX.Y-N" stream, and 0 for any other stream.
func (b ReleaseBranch) EPLine() int {
	m := epLineRe.FindStringSubmatch(b.Stream)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

// PublishStream returns the stream a build of v on branch publishes to.
// Early preview line number comes from the branch.
func PublishStream(branch string, v Version) string {
	if branch == defaults.Branch {
		return branch
	}
	if i := strings.LastIndex(branch, "-v"); i > 0 {
		if rb, ok := ParseReleaseBranch(branch[:i], branch); ok && rb.EPLine() > 0 {
			return fmt.Sprintf("%s-%d", v.PrimaryStream(), rb.EPLine())
		}
	}
	return v.Stream()
}
