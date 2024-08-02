package tasks

import (
	"fmt"
	"regexp"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/utils"
)

// ReleaseNotes generates release notes for the current release.
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

// PreReleaseValidate validates release configuration before starting a release.
func PreReleaseValidate(cfg *config.Config) {
	releaseBranch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("unable to get git branch")
	}
	match := fmt.Sprintf(`^(%s|%s-v\d+\.\d+(?:-\d+)?)$`, utils.DefaultBranch, cfg.RepoReleaseBranchPrefix)
	re := regexp.MustCompile(match)
	if !re.MatchString(releaseBranch) {
		if cfg.Registry == "" {
			logrus.Fatal("Not on a release branch and no registry specified")
		}
		logrus.Warnf("Not on a release branch, images will be pushed to %s", cfg.Registry)
	}
	logrus.WithFields(logrus.Fields{
		"releaseBranch":  releaseBranch,
		"operatorBranch": cfg.OperatorBranchName,
	}).Info("Pre-release validation complete, ready to release")
}
