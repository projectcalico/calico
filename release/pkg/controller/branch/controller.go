package branch

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

type BranchController struct {
	// repoRoot is the absolute path to the root directory of the repository
	repoRoot string

	// origin remote repository
	remote string

	// mainBranch is the main/default branch of the repository
	mainBranch string

	// devTag is the development tag identifier
	devTagIdentifier string

	// releaseBranchPrefix is the prefix for the release branch
	releaseBranchPrefix string

	// validate indicates if we should run pre-branch validation
	validate bool

	// publish indicates if we should push the branch changes to the remote repository
	publish bool
}

func NewController(opts ...Option) *BranchController {
	logrus.Debug("Creating new branch builder")
	b := &BranchController{
		validate: true,
		publish:  false,
	}

	// Apply the options
	for _, o := range opts {
		if err := o(b); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}

	// Validate the configuration
	if b.repoRoot == "" {
		logrus.Fatal("No repository root specified")
	}
	if b.remote == "" {
		logrus.Fatal("No remote repository source specified")
	}
	if b.mainBranch == "" {
		logrus.Fatal("No main branch specified")
	}
	if b.devTagIdentifier == "" {
		logrus.Fatal("No development tag identifier specified")
	}
	if b.releaseBranchPrefix == "" {
		logrus.Fatal("No release branch prefix specified")
	}

	logrus.WithFields(logrus.Fields{
		"repoRoot": b.repoRoot,
		"remote":   b.remote,
	}).Debug("Using configuration")

	return b
}

func (b *BranchController) CutBranch() error {
	if b.validate {
		if err := b.PreBranchCutValidation(); err != nil {
			logrus.WithError(err).Fatal("Failed to validate")
		}
	}
	gitVersion := version.GitVersion()
	currentVersion := gitVersion.Semver()
	newBranchName := fmt.Sprintf("%s-v%d.%d", b.releaseBranchPrefix, currentVersion.Major(), currentVersion.Minor())
	logrus.WithField("branch", newBranchName).Info("Creating new release branch")
	command.GitInDirOrFail(b.repoRoot, "checkout", "-b", newBranchName)
	if b.publish {
		command.GitInDirOrFail(b.repoRoot, "push", b.remote, newBranchName)
	}

	command.GitInDirOrFail(b.repoRoot, "checkout", b.mainBranch)
	nextVersion := currentVersion.IncMinor()
	nextVersionTag := fmt.Sprintf("v%d.%d.%d-%s", nextVersion.Major(), nextVersion.Minor(), nextVersion.Patch(), b.devTagIdentifier)
	logrus.WithField("tag", nextVersionTag).Info("Creating new development tag")
	command.GitInDirOrFail(b.repoRoot, "commit", "--allow-empty", "-m", fmt.Sprintf("Begin development on  %s", nextVersion))
	if b.publish {
		command.GitInDirOrFail(b.repoRoot, "push", b.mainBranch)
		command.GitInDirOrFail(b.repoRoot, "tag", nextVersionTag)
		command.GitInDirOrFail(b.repoRoot, "push", b.remote, nextVersionTag)
	}
	return nil
}

func (b *BranchController) PreBranchCutValidation() error {
	branch, err := utils.GitBranch(b.repoRoot)
	if err != nil {
		return err
	}
	if branch != utils.DefaultBranch {
		return fmt.Errorf("not on %s branch, all new release branch must be cut from %s branch", utils.DefaultBranch, utils.DefaultBranch)
	}
	if dirty, err := utils.GitIsDirty(b.repoRoot); err != nil {
		return err
	} else if dirty {
		return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before creating a new release branch")
	}
	gitVersion := version.GitVersion()
	if !version.HasDevTag(gitVersion, b.devTagIdentifier) {
		return fmt.Errorf("current version does not have the expected dev tag suffix %s", b.devTagIdentifier)
	}
	return nil
}
