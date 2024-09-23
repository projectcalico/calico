package tasks

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

// PreCutBranchValidate validates the configuration before creating a new release branch.
func PreCutBranchValidate(cfg *config.Config) {
	branch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("unable to get git branch")
	}
	if branch != utils.DefaultBranch {
		logrus.WithField("branch", branch).Fatalf("Not on %s branch, all new release branch must be cut from %s branch", utils.DefaultBranch, utils.DefaultBranch)
	}
	if dirty, err := utils.GitIsDirty(cfg.RepoRootDir); err != nil {
		logrus.WithError(err).Fatal("Failed to check if git is dirty")
	} else if dirty {
		logrus.Fatal("There are uncommitted changes in the repository, please commit or stash them before creating a new release branch")
	}
	currentVersion := version.GitVersion()
	if !version.HasDevTag(currentVersion, cfg.DevTagSuffix) {
		logrus.WithField("version", currentVersion).Fatalf("Current version does not have the expected dev tag suffix %s", cfg.DevTagSuffix)
	}
}

// CutReleaseBranch creates a new release branch.
func CutReleaseBranch(cfg *config.Config, publish bool) {
	currentVersion := version.GitVersion()
	nextVersion := currentVersion.Semver().IncMinor()
	nextVersionTag := fmt.Sprintf("v%s.%s.%s-%s", &nextVersion.Major(), &nextVersion.Minor(), &nextVersion.Patch(), cfg.DevTagSuffix)
	newBranchName := fmt.Sprintf("%s-v%s.%s", cfg.RepoReleaseBranchPrefix, &nextVersion.Major(), &nextVersion.Minor())
	logrus.WithFields(logrus.Fields{
		"version": nextVersionTag,
		"branch":  newBranchName,
	}).Info("Creating new release branch and version tag")
	command.GitInDirOrFail(cfg.RepoRootDir, "checkout", "-b", newBranchName)
	command.GitInDirOrFail(cfg.RepoRootDir, "commit", "--allow-empty", "-m", fmt.Sprintf("Begin development on  %s", nextVersionTag))
	command.GitInDirOrFail(cfg.RepoRootDir, "tag", nextVersionTag)
	if publish {
		command.GitInDirOrFail(cfg.RepoRootDir, "push", cfg.GitRemote, newBranchName, nextVersionTag)
		command.GitInDirOrFail(cfg.RepoRootDir, "push", cfg.GitRemote, nextVersionTag)
	}
}
