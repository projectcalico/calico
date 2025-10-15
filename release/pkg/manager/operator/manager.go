// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operator

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
)

var (
	//go:embed templates/images.go.gotmpl
	componentImagesFileTemplate string

	componentImagesFilePath = filepath.Join("pkg", "components", "images.go")
)

const (
	DefaultImage               = registry.TigeraOperatorImage
	DefaultOrg                 = utils.TigeraOrg
	DefaultRepoName            = "operator"
	DefaultRemote              = utils.DefaultRemote
	DefaultBranchName          = utils.DefaultBranch
	DefaultReleaseBranchPrefix = "release"
	DefaultDevTagSuffix        = "0.dev"
	DefaultRegistry            = "quay.io"
)

type OperatorManager struct {
	// Allow specification of command runner so it can be overridden in tests.
	runner command.CommandRunner

	// dockerRunner is for navigating docker
	docker *registry.DockerRunner

	// version is the operator version
	version string

	// dir is the absolute path to the root directory of the operator repository
	dir string

	// calicoDir is the absolute path to the root directory of the calico repository
	calicoDir string

	// tmpDir is the absolute path to the temporary directory
	tmpDir string

	// outputDir is the absolute path to the output directory
	outputDir string

	// image is the name of the operator image (e.g. tigera/operator)
	image string

	// productRegistry is the registry to use for product images
	registry string

	// productRegistry is the registry to use for product images
	productRegistry string

	// origin remote repository
	remote string

	// githubOrg is the organization of the repository
	githubOrg string

	// repoName is the name of the repository
	repoName string

	// branch is the branch to use
	branch string

	// devTag is the development tag identifier
	devTagIdentifier string

	// releaseBranchPrefix is the prefix for the release branch
	releaseBranchPrefix string

	// isHashRelease indicates if we are doing a hashrelease
	isHashRelease bool

	// validate indicates if we should run validation
	validate bool

	// validateBranch indicates if we should run branch validation
	validateBranch bool

	// publish indicates if we should push the branch changes to the remote repository
	publish bool

	// architectures is the list of architectures for which we should build images.
	// If empty, we build for all.
	architectures []string
}

func NewManager(opts ...Option) *OperatorManager {
	o := &OperatorManager{
		runner:          &command.RealCommandRunner{},
		docker:          registry.MustDockerRunner(),
		registry:        DefaultRegistry,
		image:           DefaultImage,
		productRegistry: registry.DefaultCalicoRegistries[0],
		validate:        true,
		publish:         true,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}

	return o
}

// imageParts splits the operator image into registry and image name.
// Typically the operator image is something like "tigera/operator".
// This function splits it into "tigera" and "operator".
func (o *OperatorManager) imageParts() (imagePath string, imageName string, err error) {
	parts := strings.Split(o.image, "/")
	if len(parts) != 2 {
		err = fmt.Errorf("failed to parse operator image: %s", o.image)
		return
	}
	imagePath = strings.TrimSuffix(parts[0], "/")
	imageName = strings.TrimPrefix(parts[1], "/")
	return
}

// productRegistryParts splits the product registry into registry and image path.
// Typically the product registry is something like "docker.io/calico" or "quay.io/calico".
// This function splits it into "docker.io" and "calico" or "quay.io" and "calico".
func (o *OperatorManager) productRegistryParts() (registry string, imagePath string, err error) {
	parts := strings.Split(o.productRegistry, "/")
	if len(parts) < 2 {
		err = fmt.Errorf("failed to parse product registry: %s", o.productRegistry)
		return
	}
	registry = strings.Join(parts[:len(parts)-1], "/")
	imagePath = parts[len(parts)-1]
	return
}

// modifyComponentsImagesFile overwrites the pkg/components/images.go file
// with the contents of the embedded file to ensure that operator has the right registries.
// This is ONLY used by hashreleases because the operator uses the images.go file to determine the registry.
func (o *OperatorManager) modifyComponentsImagesFile() error {
	destFilePath := filepath.Join(o.dir, componentImagesFilePath)
	dest, err := os.OpenFile(destFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", destFilePath, err)
	}
	defer func() { _ = dest.Close() }()
	tmpl, err := template.New("pkg/components/images.go").Parse(componentImagesFileTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template to overwrite %s file: %w", destFilePath, err)
	}

	imagePath, _, err := o.imageParts()
	if err != nil {
		return err
	}
	productRegistry, productImagePath, err := o.productRegistryParts()
	if err != nil {
		return err
	}

	if err := tmpl.Execute(dest, map[string]string{
		"ImagePath":        imagePath,
		"Registry":         o.registry,
		"ProductImagePath": productImagePath,
		"ProductRegistry":  productRegistry,
		"Year":             time.Now().Format("2006"),
	}); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", destFilePath, err)
	}
	return nil
}

func (o *OperatorManager) Build() error {
	if !o.isHashRelease {
		return fmt.Errorf("operator manager builds only for hash releases")
	}
	if o.validate {
		if err := o.PreBuildValidation(o.tmpDir); err != nil {
			return err
		}
	}
	component, componentsVersionPath, err := pinnedversion.GenerateOperatorComponents(o.tmpDir, o.outputDir)
	if err != nil {
		return err
	}
	if component.Image != o.image {
		return fmt.Errorf("operator image mismatch: expected %s, got %s", o.image, component.Image)
	}
	defer func() {
		if _, err := o.runner.RunInDir(o.dir, "git", []string{"reset", "--hard"}, nil); err != nil {
			logrus.WithError(err).Error("Failed to reset repository")
		}
	}()
	if err := o.modifyComponentsImagesFile(); err != nil {
		return err
	}
	env := os.Environ()
	env = append(env, fmt.Sprintf("OS_VERSIONS=%s", componentsVersionPath))
	env = append(env, fmt.Sprintf("CALICO_CRDS_DIR=%s", o.calicoDir))
	if _, err := o.make("gen-versions", env); err != nil {
		return fmt.Errorf("failed to generate versions: %w", err)
	}
	env = os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(o.architectures, " ")))
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", component.Version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", component.Image))
	if _, err := o.make("image-all", env); err != nil {
		return fmt.Errorf("failed to build images: %w", err)
	}
	for _, arch := range o.architectures {
		currentTag := fmt.Sprintf("%s:latest-%s", component.Image, arch)
		newTag := fmt.Sprintf("%s-%s", component.String(), arch)
		if err := o.docker.TagImage(currentTag, newTag); err != nil {
			return fmt.Errorf("failed to tag image %q as %q: %w", currentTag, newTag, err)
		}
	}
	env = os.Environ()
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", component.Version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", component.Image))
	env = append(env, fmt.Sprintf("BUILD_INIT_IMAGE=%s", component.InitImage().Image))
	if _, err := o.make("image-init", env); err != nil {
		return fmt.Errorf("failed to create init image: %w", err)
	}
	currentTag := fmt.Sprintf("%s:latest", component.InitImage().Image)
	newTag := component.InitImage().String()
	if err := o.docker.TagImage(currentTag, newTag); err != nil {
		return fmt.Errorf("failed to tag image %q as %q: %w", currentTag, newTag, err)
	}
	return nil
}

func (o *OperatorManager) PreBuildValidation(outputDir string) error {
	if !o.isHashRelease {
		return fmt.Errorf("operator manager builds only for hash releases")
	}
	var errStack error
	if o.dir == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no repository root specified"))
	}
	if o.validateBranch {
		branch, err := utils.GitBranch(o.dir)
		if err != nil {
			return fmt.Errorf("failed to determine branch: %s", err)
		}
		match := fmt.Sprintf(`^(%s|%s-v\d+\.\d+(?:-\d+)?)$`, utils.DefaultBranch, o.releaseBranchPrefix)
		re := regexp.MustCompile(match)
		if !re.MatchString(branch) {
			errStack = errors.Join(errStack, fmt.Errorf("not on a release branch"))
		}
		dirty, err := utils.GitIsDirty(o.dir)
		if err != nil {
			return fmt.Errorf("failed to check if git is dirty: %s", err)
		}
		if dirty {
			errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before building the hashrelease"))
		}
		return errStack
	}
	if len(o.architectures) == 0 {
		errStack = errors.Join(errStack, fmt.Errorf("no architectures specified"))
	}
	operatorComponent, err := pinnedversion.RetrievePinnedOperator(outputDir)
	if err != nil {
		return fmt.Errorf("failed to get operator component: %s", err)
	}
	if operatorComponent.Version != o.version {
		errStack = errors.Join(errStack, fmt.Errorf("operator version mismatch: expected %s, got %s", o.version, operatorComponent.Version))
	}
	return errStack
}

func (o *OperatorManager) Publish() error {
	if o.validate {
		if err := o.PrePublishValidation(); err != nil {
			return err
		}
	}
	fields := logrus.Fields{}
	if !o.publish {
		logrus.Warn("Skipping publish is set, will treat as dry-run")
		fields["dry-run"] = "true"
	}
	operatorComponent, err := pinnedversion.RetrievePinnedOperator(o.tmpDir)
	if err != nil {
		logrus.WithError(err).Error("Failed to get operator component")
		return fmt.Errorf("failed to get operator component: %w", err)
	}
	var imageList []string
	for _, arch := range o.architectures {
		imgName := fmt.Sprintf("%s-%s", operatorComponent.String(), arch)
		fields["image"] = imgName
		if o.publish {
			if err := o.docker.PushImage(imgName); err != nil {
				return err
			}
		}
		logrus.WithFields(fields).Info("Pushed operator image")
		imageList = append(imageList, imgName)
	}
	delete(fields, "image")
	manifestListName := operatorComponent.String()
	fields["manifest"] = manifestListName
	if o.publish {
		if err = o.docker.ManifestPush(manifestListName, imageList); err != nil {
			return fmt.Errorf("failed to push manifest list: %w", err)
		}
	}
	logrus.WithFields(fields).Info("Pushed operator manifest")
	delete(fields, "manifest")
	initImage := operatorComponent.InitImage()
	fields["image"] = initImage
	if o.publish {
		if err := o.docker.PushImage(initImage.String()); err != nil {
			return fmt.Errorf("failed to push init image: %w", err)
		}
	}
	logrus.WithFields(fields).Info("Pushed operator init image")
	return nil
}

func (o *OperatorManager) PrePublishValidation() error {
	if !o.isHashRelease {
		return fmt.Errorf("operator manager publishes only for hash releases")
	}
	if len(o.architectures) == 0 {
		return fmt.Errorf("no architectures specified")
	}
	if !o.publish {
		logrus.Warn("Skipping publish is set, will treat as dry-run")
	}
	return nil
}

func (o *OperatorManager) PreReleasePublicValidation() error {
	var errStack error
	if o.githubOrg == "" {
		errStack = errors.Join(errStack, fmt.Errorf("GitHub organization not specified"))
	}
	if o.repoName == "" {
		errStack = errors.Join(errStack, fmt.Errorf("GitHub repository not specified"))
	}
	if o.remote == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no git remote specified"))
	}
	if o.version == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no operator version specified"))
	}
	return errStack
}

// ReleasePublic publishes the current draft release of the operator to make it publicly available.
// It determines the latest release version, compares it with the current version, and marks the release as the latest if applicable.
func (o *OperatorManager) ReleasePublic() error {
	if !o.validate {
		if err := o.PreReleasePublicValidation(); err != nil {
			return err
		}
	}
	// Get the latest version
	args := []string{
		"release", "list", "--repo", fmt.Sprintf("%s/%s", o.githubOrg, o.repoName),
		"--exclude-drafts", "--exclude-prereleases", "--json 'name,isLatest'",
		"--jq '.[] | select(.isLatest) | .name'",
	}
	out, err := o.runner.RunInDir(o.calicoDir, "./bin/gh", args, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest release: %s", err)
	}

	// Publish the draft release
	args = []string{
		"release", "edit", o.version, "--draft=false",
		"--repo", fmt.Sprintf("%s/%s", o.githubOrg, o.repoName),
	}
	latest := version.New(strings.TrimSpace(out))
	current := version.New(o.version)
	if current.Semver().GreaterThan(latest.Semver()) {
		args = append(args, "--latest")
	}
	_, err = o.runner.RunInDir(o.calicoDir, "./bin/gh", args, nil)
	if err != nil {
		return fmt.Errorf("failed to publish %s draft release: %s", o.version, err)
	}
	return nil
}

func (o *OperatorManager) CutBranch(stream string) error {
	m := branch.NewManager(branch.WithRepoRoot(o.dir),
		branch.WithRepoRemote(o.remote),
		branch.WithMainBranch(o.branch),
		branch.WithDevTagIdentifier(o.devTagIdentifier),
		branch.WithReleaseBranchPrefix(o.releaseBranchPrefix),
		branch.WithValidate(o.validate),
		branch.WithPublish(o.publish))

	if stream == "" {
		return m.CutReleaseBranch()
	}
	return m.CutVersionedBranch(stream)
}

func (o *OperatorManager) make(target string, env []string) (string, error) {
	return o.runner.Run("make", []string{"-C", o.dir, target}, env)
}

func Clone(org, repo, branch, dir string) error {
	return utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", org, repo), branch, dir)
}
