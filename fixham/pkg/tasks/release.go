package tasks

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/calico"
	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/docs"
	"github.com/projectcalico/calico/fixham/internal/version"
)

func generateReleaseNotes(cfg *config.Config, outputDir string) {
	gitVersion, err := calico.GitVersion(cfg.RepoRootDir, "")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get git version")
	}
	releaseVersion := version.Version(gitVersion)
	filePath, err := docs.GenerateReleaseNotes(cfg.Organization, releaseVersion.Milestone(), cfg.GithubToken, cfg.RepoRootDir, outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate release notes")
	}
	logrus.WithField("release notes", filePath).Info("Generated release notes")
	logrus.Info("Please review for accuracy, and format appropriately before releasing.")
}

func ReleaseNotes(cfg *config.Config) {
	generateReleaseNotes(cfg, cfg.RepoRootDir)
}
