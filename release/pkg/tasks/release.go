package tasks

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/version"
)

// ReleaseNotes generates release notes for the current release to outDir.
func ReleaseNotes(cfg *config.Config, outDir string, version version.Version) {
	filePath, err := outputs.ReleaseNotes(cfg.Organization, cfg.GithubToken, cfg.RepoRootDir, outDir, version)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate release notes")
	}
	logrus.WithField("file", filePath).Info("Generated release notes")
	logrus.Info("Please review for accuracy, and format appropriately before releasing.")
}
