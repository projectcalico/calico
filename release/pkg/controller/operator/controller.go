package operator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashrelease"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/controller/branch"
)

type OperatorController struct {
	// Allow specification of command runner so it can be overridden in tests.
	runner command.CommandRunner

	// branchController is for controlling branching
	branchController *branch.BranchController

	// dockerRunner is for navigating docker
	docker *registry.DockerRunner

	// version is the operator version
	version string

	// repoRoot is the absolute path to the root directory of the repository
	repoRoot string

	// origin remote repository
	remote string

	// repoOrg is the organization of the repository
	repoOrg string

	// repoName is the name of the repository
	repoName string

	// mainBranch is the main/default branch of the repository
	mainBranch string

	// devTag is the development tag identifier
	devTagIdentifier string

	// releaseBranchPrefix is the prefix for the release branch
	releaseBranchPrefix string

	// isHashRelease indicates if we are doing a hashrelease
	isHashRelease bool

	// validate indicates if we should run validation
	validate bool

	// publish indicates if we should push the branch changes to the remote repository
	publish bool

	// architectures is the list of architectures for which we should build images.
	// If empty, we build for all.
	architectures []string
}

func NewController(opts ...Option) *OperatorController {
	o := &OperatorController{
		runner:   &command.RealCommandRunner{},
		docker:   registry.MustDockerRunner(),
		validate: true,
		publish:  true,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}

	if o.repoRoot == "" {
		logrus.Fatal("No repository root specified")
	}

	o.branchController = branch.NewController(branch.WithRepoRoot(o.repoRoot),
		branch.WithRepoRemote(o.remote),
		branch.WithMainBranch(o.mainBranch),
		branch.WithDevTagIdentifier(o.devTagIdentifier),
		branch.WithReleaseBranchPrefix(o.releaseBranchPrefix),
		branch.WithValidate(o.validate),
		branch.WithPublish(o.publish))

	return o
}

func (o *OperatorController) Build(monorepoRoot string) error {
	if !o.isHashRelease {
		return fmt.Errorf("operator controller builds only for hash releases")
	}
	if o.validate {
		if err := o.PreBuildValidation(); err != nil {
			return err
		}
	}
	componentsVersionPath, err := hashrelease.GenerateComponentsVersionFile(monorepoRoot)
	if err != nil {
		return err
	}
	component, err := hashrelease.RetrievePinnedOperator(monorepoRoot)
	if err != nil {
		return err
	}
	if err := o.genVersions(componentsVersionPath); err != nil {
		return err
	}
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(o.architectures, " ")))
	env = append(env, fmt.Sprintf("VERSION=%s", component.Version))
	if _, err := o.make("image-all", env); err != nil {
		return err
	}
	for _, arch := range o.architectures {
		currentTag := fmt.Sprintf("%s:latest-%s", component.Image, arch)
		newTag := fmt.Sprintf("%s-%s", component.String(), arch)
		if err := o.docker.TagImage(currentTag, newTag); err != nil {
			return err
		}
	}
	env = os.Environ()
	env = append(env, fmt.Sprintf("VERSION=%s", component.Version))
	if _, err := o.make("image-init", env); err != nil {
		return err
	}
	currentTag := fmt.Sprintf("%s:latest", component.InitImage().Image)
	newTag := component.InitImage().String()
	return o.docker.TagImage(currentTag, newTag)
}

func (o *OperatorController) PreBuildValidation() error {
	if !o.isHashRelease {
		return fmt.Errorf("operator controller builds only for hash releases")
	}
	if len(o.architectures) == 0 {
		return fmt.Errorf("no architectures specified")
	}
	operatorComponent, err := hashrelease.RetrievePinnedOperator(o.repoRoot)
	if err != nil {
		return err
	}
	if operatorComponent.Version != o.version {
		return fmt.Errorf("operator version does not match the pinned version")
	}
	return nil
}

func (o *OperatorController) Publish() error {
	if o.validate {
		if err := o.PrePublishValidation(); err != nil {
			return err
		}
	}
	operatorComponent, err := hashrelease.RetrievePinnedOperator(o.repoRoot)
	if err != nil {
		logrus.WithError(err).Error("Failed to get operator component")
		return err
	}
	var imageList []string
	for _, arch := range o.architectures {
		imgName := fmt.Sprintf("%s-%s", operatorComponent.String(), arch)
		if err := o.docker.PushImage(imgName); err != nil {
			logrus.WithField("image", imgName).WithError(err).Error("Failed to push operator image")
			return err
		}
		logrus.WithField("image", imgName).Info("Pushed operator image")
		imageList = append(imageList, imgName)
	}
	manifestListName := operatorComponent.String()
	if err = o.docker.ManifestPush(manifestListName, imageList); err != nil {
		logrus.WithField("manifest", manifestListName).WithError(err).Error("Failed to push operator manifest")
	}
	initImage := operatorComponent.InitImage()
	if err := o.docker.PushImage(initImage.String()); err != nil {
		logrus.WithField("image", initImage).WithError(err).Error("Failed to push operator init image")
		return err
	}
	return nil
}

func (o *OperatorController) PrePublishValidation() error {
	if !o.isHashRelease {
		return fmt.Errorf("operator controller publishes only for hash releases")
	}
	if len(o.architectures) == 0 {
		return fmt.Errorf("no architectures specified")
	}
	if o.publish {
		return fmt.Errorf("publishing is disabled")
	}
	return nil
}

func (o *OperatorController) genVersions(componentsVersionPath string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("OS_VERSIONS=%s", componentsVersionPath))
	env = append(env, fmt.Sprintf("COMMON_VERSIONS=%s", componentsVersionPath))
	if _, err := o.make("gen-versions", env); err != nil {
		return err
	}
	return nil
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
	if _, err := o.runner.RunInDir(clonePath, "git", []string{"clone", fmt.Sprintf("git@github.com:%s/%s.git", o.repoOrg, o.repoName), "--branch", branch}, nil); err != nil {
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

func (o *OperatorController) make(target string, env []string) (string, error) {
	return o.runner.Run("make", []string{"-C", o.repoRoot, target}, env)
}
