package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/projectcalico/calico/release/internal/utils"
)

// Version represents a version.
type Version string

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
	ver := v.String()
	return fmt.Sprintf("v%v", ver)
}

// Milestone returns the milestone of the version.
func (v *Version) Milestone() string {
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("%s v%d.%d.%d", utils.DisplayProductName(), ver.Major(), ver.Minor(), ver.Patch())
}

// Stream returns the stream of the version.
func (v *Version) Stream() string {
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("v%d.%d", ver.Major(), ver.Minor())
}

// ReleaseBranch returns the release branch of the version.
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

// NextVersion returns the next version.
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

// IsDevVersion returns true if the version is a dev version.
// A dev version is in the format of v1.2.3-<devTag>-1-g123456789012.
func IsDevVersion(ver, devTag string) bool {
	v := Version(ver)
	pattern := fmt.Sprintf(`^v\d+\.\d+\.\d+(-\d+\.\d+)?-%s-\d+-g[0-9a-f]{12}$`, devTag)
	re := regexp.MustCompile(pattern)
	return re.MatchString(v.FormattedString())
}
