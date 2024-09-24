package operator

import (
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/controller/branch"
)

type OperatorController struct {
	// Allow specification of command runner so it can be overridden in tests.
	runner command.CommandRunner

	branchController branch.BranchController

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

	// validate indicates if we should run validation
	validate bool

	// publish indicates if we should push the branch changes to the remote repository
	publish bool
}

func NewController(opts ...Option) *OperatorController {
	o := &OperatorController{
		runner: &command.RealCommandRunner{},
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}

	if o.repoRoot == "" {
		logrus.Fatal("No repository root specified")
	}
	if o.remote == "" {
		logrus.Fatal("No remote repository source specified")
	}
	if o.devTagIdentifier == "" {
		logrus.Fatal("No development tag identifier specified")
	}
	if o.releaseBranchPrefix == "" {
		logrus.Fatal("No release branch prefix specified")
	}

	o.branchController = &branch.NewController(branch.WithRepoRoot(o.repoRoot),
		branch.WithRepoRemote(o.remote),
		branch.WithMainBranch(o.mainBranch),
		branch.WithDevTagIdentifier(o.devTagIdentifier),
		branch.WithReleaseBranchPrefix(o.releaseBranchPrefix),
		branch.WithValidate(o.validate),
		branch.WithPublish(o.publish))

	return o
}

func (o *OperatorController) CutBranch() error {
	if err := o.clone(o.repoRoot, o.mainBranch); err != nil {
		return err
	}
	return o.branchController.CutBranch()
}

func (o *OperatorController) clone(repoRoot, branch string) error {
	clonePath := filepath.Dir(repoRoot)
	if err := os.MkdirAll(clonePath, utils.DirPerms); err != nil {
		return err
	}
	if _, err := os.Stat(repoRoot); !os.IsNotExist(err) {
		o.gitOrFail("checkout", branch)
		o.gitOrFail("pull")
		return nil
	}
	if _, err := o.runner.RunInDir(clonePath, "git", []string{"clone", o.remote, "--branch", branch}, nil); err != nil {
		return err
	}
	return nil
}

func (o *OperatorController) git(args ...string) (string, error) {
	return o.runner.RunInDir(o.repoRoot, "git", args, nil)
}

func (o *OperatorController) gitOrFail(args ...string) {
	_, err := o.git(args...)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to run git command")
	}
}
