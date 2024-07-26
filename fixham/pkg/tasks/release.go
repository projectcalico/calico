package tasks

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/release"
)

func ReleaseNotes(cfg *config.Config) {
	filePath, err := release.GenerateReleaseNotes(cfg.Organization, cfg.GithubToken, cfg.RepoRootDir, cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate release notes")
	}
	logrus.WithField("file", filePath).Info("Generated release notes")
	logrus.Info("Please review for accuracy, and format appropriately before releasing.")
}
