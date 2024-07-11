package version

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

type Version string

func (v *Version) Set(value string) error {
	_v, err := semver.NewVersion(strings.TrimPrefix(value, "v"))
	if err != nil {
		return err
	}
	*v = Version(_v.String())
	return nil
}

func (v *Version) String() string {
	return string(*v)
}

func (v *Version) FormattedString() string {
	if *v == "" {
		return ""
	}
	return fmt.Sprintf("v%v", *v)
}

func (v *Version) Stream() string {
	_v := semver.MustParse(string(*v))
	return fmt.Sprintf("v%d.%d", _v.Major(), _v.Minor())
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
	_v := semver.MustParse(string(*v))
	if _v.Prerelease() != "" && strings.HasPrefix(_v.Prerelease(), "1.") {
		prerelease := semver.MustParse(_v.Prerelease())
		nextPrerelease := prerelease.IncMajor()
		vNextPrerelease := fmt.Sprintf("%v.%v", nextPrerelease.Major(), nextPrerelease.Minor())
		vNext := semver.New(_v.Major(), _v.Minor(), _v.Patch(), vNextPrerelease, "")
		return Version(vNext.String())
	}
	return Version(_v.IncMinor().String())
}

func NextBranch(currentVersion string, devTagSuffix, releaseBranchPrefix string) string {
	curr := Version(strings.Split(currentVersion, devTagSuffix)[0])
	next := curr.NextVersion()
	return next.ReleaseBranch(releaseBranchPrefix)
}

func NextVersion(currentVersion, devTagSuffix string) string {
	curr := Version(strings.Split(currentVersion, devTagSuffix)[0])
	next := curr.NextVersion()
	return next.FormattedString()
}
