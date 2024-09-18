package tasks

import (
	"fmt"
	"regexp"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/utils"
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

// PreReleaseValidate validates release configuration before starting a release.
func PreReleaseValidate(cfg *config.Config) {
	releaseBranch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("unable to get git branch")
	}
	match := fmt.Sprintf(`^(%s|%s-v\d+\.\d+(?:-\d+)?)$`, utils.DefaultBranch, cfg.RepoReleaseBranchPrefix)
	re := regexp.MustCompile(match)
	if !re.MatchString(releaseBranch) {
		logrus.WithField("branch", releaseBranch).Fatal("Not on a release branch")
	}
	dirty, err := utils.GitIsDirty(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to check if git is dirty")
	} else if dirty {
		logrus.Fatal("There are uncommitted changes in the repository, please commit or stash them before building the hashrelease")
	}
	logrus.WithFields(logrus.Fields{
		"releaseBranch":  releaseBranch,
		"operatorConfig": cfg.OperatorConfig,
	}).Info("Pre-release validation complete, ready to release")
}
