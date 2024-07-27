package tasks

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/outputs"
)

func ReleaseNotes(cfg *config.Config) {
	outDir := cfg.RepoRootDir
	if cfg.IsHashrelease {
		outDir = cfg.HashreleaseDir()
	}
	filePath, err := outputs.ReleaseNotes(cfg.Organization, cfg.GithubToken, cfg.RepoRootDir, outDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate release notes")
	}
	logrus.WithField("file", filePath).Info("Generated release notes")
	logrus.Info("Please review for accuracy, and format appropriately before releasing.")
}
