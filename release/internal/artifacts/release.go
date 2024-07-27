package artifacts

import (
	"github.com/projectcalico/calico/release/internal/command"
)

// GenerateReleaseInfo generates metadata for a release.
func GenerateReleaseInfo(repoRootDir, calicoVersion, operatorVersion string) error {
	return command.Builder().BuildMetadataWithVersions(repoRootDir, calicoVersion, operatorVersion)
}
