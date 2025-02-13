// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package calico

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	errr "github.com/projectcalico/calico/release/pkg/errors"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

// Global configuration for releases.
var (
	// Default defaultRegistries to which all release images are pushed.
	defaultRegistries = []string{
		"docker.io/calico",
		"quay.io/calico",
		"gcr.io/projectcalico-org",
		"eu.gcr.io/projectcalico-org",
		"asia.gcr.io/projectcalico-org",
		"us.gcr.io/projectcalico-org",
	}

	// Directories that publish images.
	imageReleaseDirs = []string{
		"apiserver",
		"app-policy",
		"calicoctl",
		"cni-plugin",
		"key-cert-provisioner",
		"kube-controllers",
		"node",
		"pod2daemon",
		"typha",
		"goldmane",
	}

	// Directories for Windows.
	windowsReleaseDirs = []string{
		"node",
		"cni-plugin",
	}

	// images that should be expected for a release.
	// This list needs to be kept up-to-date
	// with the actual release artifacts produced for a release
	// as images are added or removed.
	images = []string{
		"apiserver",
		"cni",
		"csi",
		"ctl",
		"dikastes",
		"key-cert-provisioner",
		"kube-controllers",
		"node",
		"node-driver-registrar",
		"pod2daemon-flexvol",
		"test-signer",
		"typha",
		"goldmane",
	}
	windowsImages = []string{
		"cni-windows",
		"node-windows",
	}

	metadataFileName = "metadata.yaml"
)

func NewManager(opts ...Option) *CalicoManager {
	// Configure defaults here.
	b := &CalicoManager{
		runner:           &command.RealCommandRunner{},
		productCode:      utils.CalicoProductCode,
		validate:         true,
		validateBranch:   true,
		buildImages:      true,
		publishImages:    true,
		publishTag:       true,
		publishGithub:    true,
		imageRegistries:  defaultRegistries,
		operatorRegistry: operator.DefaultRegistry,
		operatorImage:    operator.DefaultImage,
	}

	// Run through provided options.
	for _, o := range opts {
		if err := o(b); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option to release builder")
		}
	}

	// Validate the resulting configuration.
	if b.repoRoot == "" {
		logrus.Fatal("No repo root specified")
	}
	if b.githubOrg == "" {
		logrus.Fatal("GitHub organization not specified")
	}
	if b.repo == "" {
		logrus.Fatal("GitHub repository not specified")
	}
	if b.remote == "" {
		logrus.Fatal("No git remote specified")
	}
	logrus.WithField("repoRoot", b.repoRoot).Info("Using repo root")

	if b.calicoVersion == "" {
		logrus.Fatal("No calico version specified")
	}
	logrus.WithField("version", b.calicoVersion).Info("Using product version")

	if b.operatorVersion == "" {
		logrus.Fatal("No operator version specified")
	}
	if b.buildImages && len(b.imageRegistries) == 0 {
		logrus.Fatal("No image registries specified")
	}
	logrus.WithField("operatorVersion", b.operatorVersion).Info("Using operator version")
	return b
}

type CalicoManager struct {
	// Allow specification of command runner so it can be overridden in tests.
	runner command.CommandRunner

	// The product code for the release.
	productCode string

	// The abs path of the root of the repository.
	repoRoot string

	// isHashRelease is a flag to indicate that we should build a hashrelease.
	isHashRelease bool

	// buildImages controls whether we should build container images, or use ones already built by CI.
	buildImages bool

	// validate is a flag to indicate that we should skip pre-release validation.
	validate bool

	// validateBranch is a flag to indicate that we should skip release branch validation.
	validateBranch bool

	// calicoVersion is the version of calico to release.
	calicoVersion string

	// operator variables
	operatorImage    string
	operatorRegistry string
	operatorVersion  string

	// outputDir is the directory to which we should write release artifacts, and from
	// which we should read them for publishing.
	outputDir string

	// tmpDir is the directory to which we should write temporary files.
	tmpDir string

	// Fine-tuning configuration for publishing.
	publishImages bool
	publishTag    bool
	publishGithub bool

	// imageRegistries is the list of imageRegistries to which we should publish images.
	imageRegistries []string

	// githubOrg is the GitHub organization to which we should publish releases.
	githubOrg string

	// repo is the GitHub repository to which we should publish releases.
	repo string

	// remote is the git remote to use for pushing
	remote string

	// releaseBranchPrefix is the prefix for the release branch.
	releaseBranchPrefix string

	// architectures is the list of architectures for which we should build images.
	// If empty, we build for all.
	architectures []string

	// hashrelease configuration.
	publishHashrelease bool
	hashrelease        hashreleaseserver.Hashrelease
	hashreleaseConfig  hashreleaseserver.Config

	// image scanning configuration.
	imageScanning       bool
	imageScanningConfig imagescanner.Config
	imageComponents     map[string]registry.Component

	// external configuration.
	githubToken string
}

func releaseImages(images []string, version, registry, operatorImage, operatorVersion, operatorRegistry string) []string {
	imgList := []string{fmt.Sprintf("%s/%s:%s", operatorRegistry, operatorImage, operatorVersion)}
	for _, img := range images {
		imgList = append(imgList, fmt.Sprintf("%s/%s:%s", registry, img, version))
	}
	return imgList
}

func (r *CalicoManager) helmChartVersion() string {
	return r.calicoVersion
}

func (r *CalicoManager) PreBuildValidation() error {
	if r.isHashRelease {
		return r.PreHashreleaseValidate()
	}
	return r.PreReleaseValidate()
}

func (r *CalicoManager) Build() error {
	ver := r.calicoVersion

	// Make sure output directory exists.
	var err error
	if err = os.MkdirAll(r.uploadDir(), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create output dir: %s", err)
	}

	if r.validate {
		if err := r.PreBuildValidation(); err != nil {
			return fmt.Errorf("failed pre-build validation: %s", err)
		}
	}

	if !r.isHashRelease {
		// Only tag release if this is not a hashrelease.
		// TODO: Option to skip producing a tag, for development.
		if err = r.TagRelease(ver); err != nil {
			return err
		}

		// Successfully tagged. If we fail to release after this stage, we need to delete the tag.
		defer func() {
			if err != nil {
				logrus.WithError(err).Warn("Failed to release, cleaning up tag")
				if err := r.DeleteTag(ver); err != nil {
					logrus.WithError(err).Error("Failed to clean up tag")
				}
			}
		}()
	}

	if err = r.buildContainerImages(); err != nil {
		return err
	}

	// Build the helm chart.
	if err = r.BuildHelm(); err != nil {
		return err
	}

	if r.isHashRelease {
		// This is a hashrelease.
		//
		// Re-generate manifests using the desired versions. This needs to happen
		// before building the OCP bundle, since the OCP bundle uses the manifests.
		if err = r.generateManifests(); err != nil {
			return err
		}
		defer r.resetManifests()

		// Real releases call "make release-build", but hashreleases don't.
		// Instead, we build some of the targets directly. In the future, we should instead align the release
		// and hashrelease build processes to avoid these separate code paths.
		env := append(os.Environ(), fmt.Sprintf("VERSION=%s", ver))
		targets := []string{"release-windows-archive", "dist/install-calico-windows.ps1"}
		for _, target := range targets {
			if err = r.makeInDirectoryIgnoreOutput(filepath.Join(r.repoRoot, "node"), target, env...); err != nil {
				return fmt.Errorf("error building target %s: %s", target, err)
			}
		}
	}

	// Build an OCP tgz bundle from manifests, used in the docs.
	if err = r.buildOCPBundle(); err != nil {
		return err
	}

	if err = r.collectGithubArtifacts(); err != nil {
		return err
	}
	return nil
}

type metadata struct {
	Version          string   `json:"version"`
	OperatorVersion  string   `json:"operator_version" yaml:"operatorVersion"`
	Images           []string `json:"images"`
	HelmChartVersion string   `json:"helm_chart_version" yaml:"helmChartVersion"`
}

func (r *CalicoManager) BuildMetadata(dir string) error {
	registry, err := r.getRegistryFromManifests()
	if err != nil {
		return err
	}

	m := metadata{
		Version:          r.calicoVersion,
		OperatorVersion:  r.operatorVersion,
		Images:           releaseImages(append(images, windowsImages...), r.calicoVersion, registry, r.operatorImage, r.operatorVersion, r.operatorRegistry),
		HelmChartVersion: r.helmChartVersion(),
	}

	// Render it as yaml and write it to a file.
	bs, err := yaml.Marshal(m)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(dir, metadataFileName), []byte(bs), 0o644)
	if err != nil {
		return err
	}

	return nil
}

func (r *CalicoManager) getRegistryFromManifests() (string, error) {
	args := []string{"-Po", `image:\K(.*)`, "calicoctl.yaml"}
	out, err := r.runner.RunInDir(filepath.Join(r.repoRoot, "manifests"), "grep", args, nil)
	if err != nil {
		return "", err
	}
	imgs := strings.Split(out, "\n")
	for _, i := range imgs {
		parts := strings.Split(i, "/")
		if len(parts) > 1 {
			return strings.Join(parts[:len(parts)-1], "/"), nil
		}
	}
	return "", fmt.Errorf("failed to find registry from manifests")
}

func (r *CalicoManager) PreHashreleaseValidate() error {
	var errStack error
	if r.validateBranch {
		branch, err := utils.GitBranch(r.repoRoot)
		if err != nil {
			return fmt.Errorf("failed to determine branch: %s", err)
		}
		match := fmt.Sprintf(`^(%s|%s-v\d+\.\d+(?:-\d+)?)$`, utils.DefaultBranch, r.releaseBranchPrefix)
		re := regexp.MustCompile(match)
		if !re.MatchString(branch) {
			errStack = errors.Join(errStack, fmt.Errorf("not on a release branch"))
		}
	}
	dirty, err := utils.GitIsDirty(r.repoRoot)
	if err != nil {
		return fmt.Errorf("failed to check if git is dirty: %s", err)
	}
	if dirty {
		errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before building the hashrelease"))
	}
	if err := r.checkCodeGeneration(); err != nil {
		errStack = errors.Join(errStack, err)
	}
	return errStack
}

func (r *CalicoManager) checkCodeGeneration() error {
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "generate get-operator-crds check-dirty"); err != nil {
		logrus.WithError(err).Error("Failed to check code generation")
		return fmt.Errorf("code generation error, try 'make generate get-operator-crds' to fix")
	}
	return nil
}

func (r *CalicoManager) PreReleaseValidate() error {
	// Cheeck that we are on a release branch
	if r.validateBranch {
		branch, err := utils.GitBranch(r.repoRoot)
		if err != nil {
			return fmt.Errorf("failed to determine branch: %s", err)
		}
		// releases can only be cut from a release branch (i.e release-vX.Y) or build version branch (i.e. build-vX.Y.Z)
		match := fmt.Sprintf(`^(%s-v\d+\.\d+(?:-\d+)?|build-v\d+\.\d+\.\d+)$`, r.releaseBranchPrefix)
		re := regexp.MustCompile(match)
		if !re.MatchString(branch) {
			return fmt.Errorf("current branch (%s) is not a release branch", branch)
		}
	}

	// Check that we're not already on a git tag.
	out, err := r.git("describe", "--exact-match", "--tags", "HEAD")
	if err == nil {
		// On a current tag.
		return fmt.Errorf("Already on a tag (%s), refusing to create release", out)
	}

	// Check that the repository is not a shallow clone. We need correct history.
	out, err = r.git("rev-parse", "--is-shallow-repository")
	if err != nil {
		return fmt.Errorf("rev-parse failed: %s", err)
	}
	if strings.TrimSpace(out) == "true" {
		return fmt.Errorf("Attempt to release from a shallow clone is not possible")
	}

	// Check that code generation is up-to-date.
	if err := r.checkCodeGeneration(); err != nil {
		return err
	}

	// Assert that manifests are using the correct version.
	err = r.assertManifestVersions(r.calicoVersion)
	if err != nil {
		return err
	}

	err = r.assertReleaseNotesPresent(r.calicoVersion)
	if err != nil {
		return err
	}

	return r.releasePrereqs()
}

func (r *CalicoManager) DeleteTag(ver string) error {
	_, err := r.git("tag", "-d", ver)
	if err != nil {
		return fmt.Errorf("Failed to delete tag: %s", err)
	}
	return nil
}

func (r *CalicoManager) TagRelease(ver string) error {
	branch := r.determineBranch()
	logrus.WithFields(logrus.Fields{"branch": branch, "version": ver}).Infof("Creating Calico release from branch")
	_, err := r.git("tag", ver)
	if err != nil {
		return fmt.Errorf("Failed to tag release: %s", err)
	}
	return nil
}

// modifyHelmChartsValues modifies values in helm charts to use the correct version.
// This is only necessary for hashreleases.
func (r *CalicoManager) modifyHelmChartsValues() error {
	valuesYAML := filepath.Join(r.repoRoot, "charts", "tigera-operator", "values.yaml")
	if _, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/version: .*/version: %s/g`, r.operatorVersion), valuesYAML}, nil); err != nil {
		logrus.WithError(err).Error("Failed to update operator version in values.yaml")
		return err
	}
	if _, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/tag: .*/tag: %s/g`, r.calicoVersion), valuesYAML}, nil); err != nil {
		logrus.WithError(err).Error("Failed to update calicoctl version in values.yaml")
		return err
	}
	return nil
}

func (r *CalicoManager) BuildHelm() error {
	if r.isHashRelease {
		if err := r.modifyHelmChartsValues(); err != nil {
			return fmt.Errorf("failed to modify helm chart values: %s", err)
		}
	}

	// Build the helm chart, passing the version to use.
	env := append(os.Environ(), fmt.Sprintf("GIT_VERSION=%s", r.calicoVersion))
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "chart", env...); err != nil {
		return err
	}

	if r.isHashRelease {
		// If we modified the repo above, reset it.
		if _, err := r.runner.RunInDir(r.repoRoot, "git", []string{"checkout", "charts/"}, nil); err != nil {
			logrus.WithError(err).Error("Failed to reset changes to charts")
			return err
		}
	}
	return nil
}

func (r *CalicoManager) buildOCPBundle() error {
	// Build OpenShift bundle.
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "bin/ocp.tgz"); err != nil {
		return err
	}
	return nil
}

func (r *CalicoManager) publishToHashreleaseServer() error {
	if !r.publishHashrelease {
		logrus.Info("Skipping publishing to hashrelease server")
		return nil
	}
	logrus.WithField("note", r.hashrelease.Note).Info("Publishing hashrelease")
	dir := r.hashrelease.Source + "/"
	if _, err := r.runner.Run("rsync",
		[]string{
			"--stats", "-az", "--delete",
			fmt.Sprintf("--rsh=%s", r.hashreleaseConfig.RSHCommand()), dir,
			fmt.Sprintf("%s:%s/%s", r.hashreleaseConfig.HostString(), hashreleaseserver.RemoteDocsPath(r.hashreleaseConfig.User), r.hashrelease.Name),
		}, nil); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return err
	}
	if r.hashrelease.Latest {
		return hashreleaseserver.SetHashreleaseAsLatest(r.hashrelease, r.productCode, &r.hashreleaseConfig)
	}
	return nil
}

func (r *CalicoManager) PublishRelease() error {
	// Check that the environment has the necessary prereqs.
	if err := r.publishPrereqs(); err != nil {
		return err
	}

	// Publish container images.
	if err := r.publishContainerImages(); err != nil {
		return fmt.Errorf("failed to publish container images: %s", err)
	}

	if r.isHashRelease {
		if err := r.publishToHashreleaseServer(); err != nil {
			return fmt.Errorf("failed to publish hashrelease: %s", err)
		}
	} else {
		// Publish the git tag.
		if err := r.publishGitTag(); err != nil {
			return fmt.Errorf("failed to publish git tag: %s", err)
		}

		// Publish the release to github.
		if err := r.publishGithubRelease(); err != nil {
			return fmt.Errorf("failed to publish github release: %s", err)
		}
	}

	return nil
}

// Check general prerequisites for cutting and publishing a release.
func (r *CalicoManager) releasePrereqs() error {
	// Check that we're not on the master branch. We never cut releases from master.
	branch := r.determineBranch()
	if branch == "master" {
		return fmt.Errorf("cannot cut release from branch: %s", branch)
	}

	// If we are releasing to projectcalico/calico, make sure we are releasing to the default registries.
	if r.githubOrg == utils.ProjectCalicoOrg && r.repo == utils.CalicoRepoName {
		if !reflect.DeepEqual(r.imageRegistries, defaultRegistries) {
			return fmt.Errorf("image registries cannot be different from default registries for a release")
		}
	}

	return nil
}

type imageExistsResult struct {
	name   string
	image  string
	exists bool
	err    error
}

// checkHashreleaseImagesPublished checks that the images required for the hashrelease exist in the specified registries.
func (r *CalicoManager) checkHashreleaseImagesPublished() ([]registry.Component, error) {
	logrus.Info("Checking images required for hashrelease have already been published")
	numOfComponents := len(r.imageComponents)
	if numOfComponents == 0 {
		logrus.Error("No images to check")
		return nil, fmt.Errorf("no images to check")
	}

	resultsCh := make(chan imageExistsResult, numOfComponents)

	for name, component := range r.imageComponents {
		go func(name string, component registry.Component, ch chan imageExistsResult) {
			exists, err := registry.ImageExists(component.ImageRef())
			resultsCh <- imageExistsResult{
				name:   name,
				image:  component.String(),
				exists: exists,
				err:    err,
			}
		}(name, component, resultsCh)
	}

	var resultsErr error
	missingImages := []registry.Component{}
	for range r.imageComponents {
		result := <-resultsCh
		if result.err != nil {
			resultsErr = errors.Join(resultsErr, fmt.Errorf("error checking %s exists: %s", result.image, result.err.Error()))
		} else if !result.exists {
			missingImages = append(missingImages, r.imageComponents[result.name])
		}
	}
	return missingImages, resultsErr
}

// Check that the environment has the necessary prereqs for publishing hashrelease
func (r *CalicoManager) hashreleasePrereqs() error {
	if r.publishHashrelease {
		if !r.hashreleaseConfig.Valid() {
			return fmt.Errorf("missing hashrelease server configuration")
		}
	}

	if r.publishImages {
		return r.assertImageVersions()
	} else {
		missingImages, err := r.checkHashreleaseImagesPublished()
		if err != nil {
			return fmt.Errorf("errors checking images: %s", err)
		} else if len(missingImages) > 0 {
			return errr.ErrHashreleaseMissingImages{
				Hashrelease:   r.hashrelease,
				MissingImages: missingImages,
			}
		}
		logrus.Info("All images required for hashrelease have been published")
	}

	if r.imageScanning {
		logrus.Info("Sending images to ISS")
		imageList := []string{}
		for _, component := range r.imageComponents {
			imageList = append(imageList, component.String())
		}
		imageScanner := imagescanner.New(r.imageScanningConfig)
		err := imageScanner.Scan(r.productCode, imageList, r.hashrelease.Stream, false, r.tmpDir)
		if err != nil {
			// Error is logged and ignored as this is not considered a fatal error
			logrus.WithError(err).Error("Failed to scan images")
		}
	}

	return nil
}

// Check that the images exists with the correct version.
func (r *CalicoManager) assertImageVersions() error {
	logrus.Info("Checking built images exists with the correct version")
	for _, img := range images {
		switch img {
		case "apiserver":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
				// apiserver always returns an error because there is no kubeconfig, log and ignore it.
				if err != nil {
					logrus.WithError(err).WithField("image", img).Warn("error getting version from image")
				}
				if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "cni":
			for _, reg := range r.imageRegistries {
				for _, cmd := range []string{"calico", "calico-ipam"} {
					out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), cmd, "-v"}, nil)
					if err != nil {
						return fmt.Errorf("failed to run get version from %s image: %s", cmd, err)
					} else if !strings.Contains(out, r.calicoVersion) {
						return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
					}
				}
			}
		case "csi":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "version" }}'`, fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "ctl":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "dikastes":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "version" }}'`, fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "key-cert-provisioner":
			// key-cert-provisioner does not have version information in the image.
		case "kube-controllers":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "--version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "node":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "versions"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "node-driver-registrar":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "version" }}'`, fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "pod2daemon-flexvol":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "version" }}'`, fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "test-signer":
			// test-signer does not have version information in the image.
		case "typha":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "calico-typha", "--version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "goldmane":
			// goldmane does not have version information in the image.
		default:
			return fmt.Errorf("unknown image: %s, update assertion to include validating image", img)
		}
	}
	return nil
}

// Prerequisites specific to publishing a release.
func (r *CalicoManager) publishPrereqs() error {
	if !r.validate {
		logrus.Warn("Skipping pre-publish validation")
		return nil
	}
	if dirty, err := utils.GitIsDirty(r.repoRoot); dirty || err != nil {
		return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before publishing the release")
	}
	if r.isHashRelease {
		return r.hashreleasePrereqs()
	}
	// TODO: Verify all required artifacts are present.
	if err := r.releasePrereqs(); err != nil {
		return err
	}
	return r.assertImageVersions()
}

// We include the following GitHub artifacts on each release. This function assumes
// that they have already been built, and simply wraps them up.
//
// - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
// - tigera-operator-vX.Y.Z.tgz: contains the helm v3 chart.
// - calico-windows-vX.Y.Z.zip: Calico for Windows zip archive for non-HPC installation.
// - calicoctl/bin: All calicoctl binaries.
//
// For hashreleases, we don't build the release tarball, but we do include the manifests directly.
//
// This function also generates checksums for each artifact that is uploaded to the release.
func (r *CalicoManager) collectGithubArtifacts() error {
	// Artifacts will be moved here.
	uploadDir := r.uploadDir()

	// Add in a release metadata file.
	err := r.BuildMetadata(uploadDir)
	if err != nil {
		return fmt.Errorf("failed to build release metadata file: %s", err)
	}

	// We attach calicoctl binaries directly to the release as well.
	if !r.isHashRelease {
		// TODO: We don't currently build calicoctl for hashreleases.
		files, err := os.ReadDir(filepath.Join(r.repoRoot, "calicoctl", "bin"))
		if err != nil {
			return err
		}
		for _, b := range files {
			if _, err := r.runner.Run("cp", []string{filepath.Join(r.repoRoot, "calicoctl", "bin", b.Name()), uploadDir}, nil); err != nil {
				return err
			}
		}

		// Build and add in the complete release tarball.
		if err = r.buildReleaseTar(r.calicoVersion, uploadDir); err != nil {
			return err
		}
	} else {
		// Hashrelease - output dir is a little different for now.
		// TODO: Manifests included here, instead of in release tarball.
		if _, err := r.runner.Run("cp", []string{"-r", filepath.Join(r.repoRoot, "manifests"), uploadDir}, nil); err != nil {
			logrus.WithError(err).Error("Failed to copy manifests to output directory")
			return err
		}
	}

	// Add in the already-built windows zip archive, the Windows install script, ocp bundle, and the helm chart.
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{fmt.Sprintf("node/dist/calico-windows-%s.zip", r.calicoVersion), uploadDir}, nil); err != nil {
		return err
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"node/dist/install-calico-windows.ps1", uploadDir}, nil); err != nil {
		return err
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"bin/ocp.tgz", uploadDir}, nil); err != nil {
		return err
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{fmt.Sprintf("bin/tigera-operator-%s.tgz", r.calicoVersion), uploadDir}, nil); err != nil {
		return err
	}

	// Generate a SHA256SUMS file containing the checksums for each artifact
	// that we attach to the release. These can be confirmed by end users via the following command:
	// sha256sum -c --ignore-missing SHA256SUMS
	files, err := os.ReadDir(uploadDir)
	if err != nil {
		return err
	}
	sha256args := []string{}
	for _, f := range files {
		if !f.IsDir() {
			sha256args = append(sha256args, f.Name())
		}
	}
	output, err := r.runner.RunInDir(uploadDir, "sha256sum", sha256args, nil)
	if err != nil {
		return err
	}
	err = os.WriteFile(fmt.Sprintf("%s/SHA256SUMS", uploadDir), []byte(output), 0o644)
	if err != nil {
		return err
	}

	return nil
}

// generateManifests re-generates manifests using the specified calico and operator versions.
func (r *CalicoManager) generateManifests() error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("CALICO_VERSION=%s", r.calicoVersion))
	env = append(env, fmt.Sprintf("OPERATOR_VERSION=%s", r.operatorVersion))
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "gen-manifests", env...); err != nil {
		logrus.WithError(err).Error("Failed to make manifests")
		return err
	}
	return nil
}

func (r *CalicoManager) resetManifests() {
	if _, err := r.runner.RunInDir(r.repoRoot, "git", []string{"checkout", "manifests"}, nil); err != nil {
		logrus.WithError(err).Error("Failed to reset manifests")
	}
}

func (r *CalicoManager) uploadDir() string {
	if r.outputDir == "" {
		logrus.Panic("No output directory specified")
	}
	return r.outputDir
}

// Builds the complete release tar for upload to github.
// - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
// TODO: We should produce a tar per architecture that we ship.
// TODO: We should produce windows tars
func (r *CalicoManager) buildReleaseTar(ver string, targetDir string) error {
	// Create tar files for container image that are shipped.
	releaseBase := filepath.Join(r.repoRoot, "release", "_output", fmt.Sprintf("release-%s", ver))
	err := os.MkdirAll(releaseBase+"/images", os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create images dir: %s", err)
	}
	imgDir := filepath.Join(releaseBase, "images")
	registry := r.imageRegistries[0]
	images := map[string]string{
		fmt.Sprintf("%s/node:%s", registry, ver):                         filepath.Join(imgDir, "calico-node.tar"),
		fmt.Sprintf("%s/typha:%s", registry, ver):                        filepath.Join(imgDir, "calico-typha.tar"),
		fmt.Sprintf("%s/cni:%s", registry, ver):                          filepath.Join(imgDir, "calico-cni.tar"),
		fmt.Sprintf("%s/kube-controllers:%s", registry, ver):             filepath.Join(imgDir, "calico-kube-controllers.tar"),
		fmt.Sprintf("%s/pod2daemon-flexvol:%s", registry, ver):           filepath.Join(imgDir, "calico-pod2daemon.tar"),
		fmt.Sprintf("%s/dikastes:%s", registry, ver):                     filepath.Join(imgDir, "calico-dikastes.tar"),
		fmt.Sprintf("%s/flannel-migration-controller:%s", registry, ver): filepath.Join(imgDir, "calico-flannel-migration-controller.tar"),
	}
	for img, out := range images {
		err = r.archiveContainerImage(out, img)
		if err != nil {
			return err
		}
	}

	// Add in release binaries that we ship.
	binDir := filepath.Join(releaseBase, "bin")
	err = os.MkdirAll(binDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create images dir: %s", err)
	}

	binaries := map[string]string{
		// CNI plugin binaries are all placed in github dir.
		"cni-plugin/bin/": filepath.Join(binDir, "cni"),

		// Calicoctl binaries.
		"calicoctl/bin/": filepath.Join(binDir, "calicoctl"),

		// Felix binaries.
		"felix/bin/calico-bpf": binDir,
	}
	for src, dst := range binaries {
		if _, err := r.runner.Run("cp", []string{"-r", src, dst}, nil); err != nil {
			return err
		}
	}

	// Add in manifests directory generated from the docs.
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"-r", "manifests", releaseBase}, nil); err != nil {
		return err
	}

	// tar up the whole thing, and copy it to the target directory
	if _, err := r.runner.RunInDir(r.repoRoot, "tar", []string{"-czvf", fmt.Sprintf("release/_output/release-%s.tgz", ver), "-C", "release/_output", fmt.Sprintf("release-%s", ver)}, nil); err != nil {
		return err
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{fmt.Sprintf("release/_output/release-%s.tgz", ver), targetDir}, nil); err != nil {
		return err
	}
	return nil
}

func (r *CalicoManager) buildContainerImages() error {
	if !r.buildImages {
		logrus.Info("Skip building container images")
		return nil
	}
	releaseDirs := append(imageReleaseDirs, "felix")

	logrus.Info("Building container images")

	// Build env.
	env := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", r.calicoVersion),
		fmt.Sprintf("DEV_REGISTRIES=%s", strings.Join(r.imageRegistries, " ")),
	)

	if len(r.architectures) > 0 {
		env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(r.architectures, " ")))
	}

	for _, dir := range releaseDirs {
		// Use an absolute path for the directory to build.
		out, err := r.makeInDirectoryWithOutput(filepath.Join(r.repoRoot, dir), "release-build", env...)
		if err != nil {
			logrus.Error(out)
			return fmt.Errorf("Failed to build %s: %s", dir, err)
		}
		logrus.Info(out)
	}

	for _, dir := range windowsReleaseDirs {
		out, err := r.makeInDirectoryWithOutput(filepath.Join(r.repoRoot, dir), "image-windows", env...)
		if err != nil {
			logrus.Error(out)
			return fmt.Errorf("Failed to build %s: %s", dir, err)
		}
		logrus.Info(out)
	}
	return nil
}

func (r *CalicoManager) publishGitTag() error {
	if !r.publishTag {
		logrus.Info("Skipping git tag")
		return nil
	}
	_, err := r.git("push", r.remote, r.calicoVersion)
	return err
}

func (r *CalicoManager) publishGithubRelease() error {
	if !r.publishGithub {
		logrus.Info("Skipping github release")
		return nil
	}

	releaseNoteTemplate := `
Release notes can be found [on GitHub](https://github.com/projectcalico/calico/blob/{version}/release-notes/{version}-release-notes.md)

Attached to this release are the following artifacts:

- {release_tar}: container images, binaries, and kubernetes manifests.
- {calico_windows_zip}: Calico for Windows.
- {helm_chart}: Calico Helm v3 chart.
- ocp.tgz: Manifest bundle for OpenShift.

Additional links:

- [VPP data plane release information](https://github.com/projectcalico/vpp-dataplane/blob/master/RELEASE_NOTES.md)

`
	sv, err := semver.NewVersion(strings.TrimPrefix(r.calicoVersion, "v"))
	if err != nil {
		return err
	}
	formatters := []string{
		// Alternating placeholder / filler. We can't use backticks in the multiline string above,
		// so we replace anything that needs to be backticked into it here.
		"{version}", r.calicoVersion,
		"{branch}", fmt.Sprintf("release-v%d.%d", sv.Major, sv.Minor),
		"{release_stream}", fmt.Sprintf("v%d.%d", sv.Major, sv.Minor),
		"{release_tar}", fmt.Sprintf("`release-%s.tgz`", r.calicoVersion),
		"{calico_windows_zip}", fmt.Sprintf("`calico-windows-%s.zip`", r.calicoVersion),
		"{helm_chart}", fmt.Sprintf("`tigera-operator-%s.tgz`", r.calicoVersion),
	}
	replacer := strings.NewReplacer(formatters...)
	releaseNote := replacer.Replace(releaseNoteTemplate)

	args := []string{
		"-username", r.githubOrg,
		"-repository", r.repo,
		"-name", r.calicoVersion,
		"-body", releaseNote,
		"-draft",
		r.calicoVersion,
		r.uploadDir(),
	}
	_, err = r.runner.RunInDir(r.repoRoot, "./bin/ghr", args, nil)
	return err
}

func (r *CalicoManager) publishContainerImages() error {
	if !r.publishImages {
		logrus.Info("Skipping image publish")
		return nil
	}

	env := append(os.Environ(),
		fmt.Sprintf("IMAGETAG=%s", r.calicoVersion),
		fmt.Sprintf("VERSION=%s", r.calicoVersion),
		"RELEASE=true",
		"CONFIRM=true",
		fmt.Sprintf("DEV_REGISTRIES=%s", strings.Join(r.imageRegistries, " ")),
	)

	// We allow for a certain number of retries when publishing each directory, since
	// network flakes can occasionally result in images failing to push.
	maxRetries := 1
	for _, dir := range imageReleaseDirs {
		attempt := 0
		for {
			out, err := r.makeInDirectoryWithOutput(filepath.Join(r.repoRoot, dir), "release-publish", env...)
			if err != nil {
				if attempt < maxRetries {
					logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
					attempt++
					continue
				}
				logrus.Error(out)
				return fmt.Errorf("Failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
	}
	for _, dir := range windowsReleaseDirs {
		attempt := 0
		for {
			out, err := r.makeInDirectoryWithOutput(filepath.Join(r.repoRoot, dir), "release-windows", env...)
			if err != nil {
				if attempt < maxRetries {
					logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
					attempt++
					continue
				}
				logrus.Error(out)
				return fmt.Errorf("Failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
	}
	return nil
}

func (r *CalicoManager) assertReleaseNotesPresent(ver string) error {
	// Validate that the release notes for this version are present,
	// fail if not.

	releaseNotesPath := filepath.Join(r.repoRoot, "release-notes", fmt.Sprintf("%s-release-notes.md", ver))
	releaseNotesStat, err := os.Stat(releaseNotesPath)
	// If we got an error, handle that?
	if err != nil {
		return fmt.Errorf("release notes file is invalid: %s", err.Error())
	}
	if releaseNotesStat.Size() == 0 {
		return fmt.Errorf("release notes file is invalid: file is 0 bytes")
	} else if releaseNotesStat.IsDir() {
		return fmt.Errorf("release notes file is invalid: %s is a directory", releaseNotesPath)
	}
	return nil
}

func (r *CalicoManager) assertManifestVersions(ver string) error {
	// Go through a subset of yaml files in manifests/ and extract the images
	// that they use. Verify that the images are using the given version.
	// We also do the manifests/ocp/ yaml to check the calico/ctl image is correct.
	manifests := []string{"calico.yaml", "ocp/02-tigera-operator.yaml"}

	for _, m := range manifests {
		args := []string{"-Po", `image:\K(.*)`, m}
		out, err := r.runner.RunInDir(filepath.Join(r.repoRoot, "manifests"), "grep", args, nil)
		if err != nil {
			return err
		}
		imgs := strings.Split(out, "\n")
		for _, i := range imgs {
			if strings.Contains(i, "operator") {
				// We don't handle the operator image here yet, since
				// the version is different.
				continue
			}
			if !strings.HasSuffix(i, ver) {
				return fmt.Errorf("Incorrect image version (expected %s) in manifest %s: %s", ver, m, i)
			}
		}
	}

	return nil
}

// determineBranch returns the current checked out branch.
func (r *CalicoManager) determineBranch() string {
	out, err := r.git("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		logrus.WithError(err).Fatal("Error determining branch")
	} else if strings.TrimSpace(out) == "HEAD" {
		logrus.Fatal("Not on a branch, refusing to cut release")
	}
	return strings.TrimSpace(out)
}

// Uses docker to build a tgz archive of the specified container image.
func (r *CalicoManager) archiveContainerImage(out, image string) error {
	_, err := r.runner.Run("docker", []string{"save", "--output", out, image}, nil)
	return err
}

func (r *CalicoManager) git(args ...string) (string, error) {
	return r.runner.Run("git", args, nil)
}

func (r *CalicoManager) makeInDirectoryWithOutput(dir, target string, env ...string) (string, error) {
	targets := strings.Split(target, " ")
	args := []string{"-C", dir}
	args = append(args, targets...)
	return r.runner.Run("make", args, env)
}

func (r *CalicoManager) makeInDirectoryIgnoreOutput(dir, target string, env ...string) error {
	_, err := r.makeInDirectoryWithOutput(dir, target, env...)
	return err
}
