package outputs

import (
	"github.com/projectcalico/calico/release/internal/command"
)

// Metadata generates metadata for a release.
func Metadata(repoRootDir, version, operatorVersion string) error {
	return command.Builder().BuildMetadataWithVersions(repoRootDir, version, operatorVersion)
}
