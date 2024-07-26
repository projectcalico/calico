package release

import (
	"github.com/projectcalico/calico/fixham/internal/command"
)

// Metadata generates metadata for a release.
func Metadata(repoRootDir, calicoVersion, operatorVersion string) error {
	return command.Builder().BuildMetadataWithVersions(repoRootDir, calicoVersion, operatorVersion)
}
