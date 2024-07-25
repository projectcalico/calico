package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/projectcalico/calico/fixham/internal/utils"
)

type Version string

func (v *Version) Set() string {
	ver, err := semver.NewVersion(strings.TrimPrefix(string(*v), "v"))
	if err != nil {
		return ""
	}
	return ver.String()
}

func (v *Version) String() string {
	ver, err := semver.NewVersion(strings.TrimPrefix(string(*v), "v"))
	if err != nil {
		return ""
	}
	return ver.String()
}

func (v *Version) FormattedString() string {
	ver := v.String()
	return fmt.Sprintf("v%v", ver)
}

func (v *Version) Milestone() string {
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("%s v%d.%d.%d", cases.Title(language.English).String(utils.ProductName), ver.Major(), ver.Minor(), ver.Patch())
}

func (v *Version) Stream() string {
	ver := semver.MustParse(string(*v))
	return fmt.Sprintf("v%d.%d", ver.Major(), ver.Minor())
}

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

func IsDevVersion(ver, devTag string) bool {
	v := Version(ver)
	pattern := fmt.Sprintf(`^v\d+\.\d+\.\d+(-\d+\.\d+)?%s-\d+-g[0-9a-f]{12}$`, devTag)
	re := regexp.MustCompile(pattern)
	return re.MatchString(v.FormattedString())
}
