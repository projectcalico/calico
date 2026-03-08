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
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

// Global configuration for releases.
var (
	// Default defaultRegistries to which all release images are pushed.
	defaultRegistries = registry.DefaultCalicoRegistries

	// Directories that publish images.
	imageReleaseDirs = utils.ImageReleaseDirs

	// Directories that publish windows images.
	windowsReleaseDirs = []string{
		"node",
		"cni-plugin",
	}

	metadataFileName = "metadata.yaml"

	helmIndexFileName = "index.yaml"

	s3ACLPublicRead = []string{"--acl", "public-read"}
)

func NewManager(opts ...Option) *CalicoManager {
	// Configure defaults here.
	b := &CalicoManager{
		runner:            &command.RealCommandRunner{},
		productCode:       utils.CalicoProductCode,
		validate:          true,
		validateBranch:    true,
		buildImages:       true,
		publishImages:     true,
		publishCharts:     true,
		archiveImages:     true,
		publishTag:        true,
		publishGithub:     true,
		imageRegistries:   defaultRegistries,
		helmRegistries:    registry.DefaultHelmRegistries,
		helmRepoURL:       utils.CalicoHelmRepoURL,
		operatorRegistry:  operator.DefaultRegistry,
		operatorImage:     operator.DefaultImage,
		operatorGithubOrg: operator.DefaultOrg,
		operatorRepo:      operator.DefaultRepoName,
		operatorBranch:    operator.DefaultBranchName,
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
	logrus.WithField("repoRoot", b.repoRoot).Info("Using repo root")
	if b.githubOrg == "" {
		logrus.Fatal("GitHub organization not specified")
	}
	if b.repo == "" {
		logrus.Fatal("GitHub repository not specified")
	}
	if b.remote == "" {
		logrus.Fatal("No git remote specified")
	}
	logrus.WithFields(logrus.Fields{
		"org":    b.githubOrg,
		"repo":   b.repo,
		"remote": b.remote,
	}).Info("Using GitHub configuration")

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

	// archiveImages controls whether we should archive container images in release tarball.
	archiveImages bool

	// validate is a flag to indicate that we should skip pre-release validation.
	validate bool

	// validateBranch is a flag to indicate that we should skip release branch validation.
	validateBranch bool

	// calicoVersion is the version of calico to release.
	calicoVersion string

	// operator variables
	operatorImage     string
	operatorRegistry  string
	operatorVersion   string
	operatorGithubOrg string
	operatorRepo      string
	operatorBranch    string

	// outputDir is the directory to which we should write release artifacts, and from
	// which we should read them for publishing.
	outputDir string

	// tmpDir is the directory to which we should write temporary files.
	tmpDir string

	// Fine-tuning configuration for publishing.
	publishImages bool
	publishCharts bool
	publishTag    bool
	publishGithub bool
	awsProfile    string
	s3Bucket      string

	// imageRegistries is the list of imageRegistries to which we should publish images.
	imageRegistries []string

	// helmRegistries is the list of OCI-based registries to which we should publish charts.
	helmRegistries []string

	// helmRepoURL is the URL of the helm chart repository.
	helmRepoURL string

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
	var errStack error
	if r.calicoVersion == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no calico version specified"))
	}

	if r.operatorVersion == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no operator version specified"))
	}
	if (r.buildImages || r.archiveImages) && len(r.imageRegistries) == 0 {
		errStack = errors.Join(errStack, fmt.Errorf("no image registries specified"))
	}
	if errStack != nil {
		return errStack
	}
	logrus.WithField("version", r.calicoVersion).Info("Using product version")
	logrus.WithField("operatorVersion", r.operatorVersion).Info("Using operator version")
	logrus.WithField("registries", r.imageRegistries).Info("Using image registries for release")
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

	// Build binaries for release.
	if err := r.buildBinaries(); err != nil {
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

	// Build and add in the complete release tarball.
	if err = r.buildReleaseTar(); err != nil {
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
		return fmt.Errorf("failed to get registry from manifests: %w", err)
	}

	m := metadata{
		Version:          r.calicoVersion,
		OperatorVersion:  r.operatorVersion,
		Images:           releaseImages(utils.ReleaseImages(), r.calicoVersion, registry, r.operatorImage, r.operatorVersion, r.operatorRegistry),
		HelmChartVersion: r.helmChartVersion(),
	}

	// Render it as yaml and write it to a file.
	bs, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %s", err)
	}

	err = os.WriteFile(filepath.Join(dir, metadataFileName), []byte(bs), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write metadata file: %s", err)
	}

	return nil
}

func (r *CalicoManager) getRegistryFromManifests() (string, error) {
	args := []string{"-Po", `image:\K(.*)`, "calicoctl.yaml"}
	out, err := r.runner.RunInDir(filepath.Join(r.repoRoot, "manifests"), "grep", args, nil)
	if err != nil {
		return "", fmt.Errorf("error getting registry from calicoctl.yaml manifest: %w", err)
	}
	imgs := strings.SplitSeq(out, "\n")
	for i := range imgs {
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
	env := append(os.Environ(),
		fmt.Sprintf("OPERATOR_ORGANIZATION=%s", r.operatorGithubOrg),
		fmt.Sprintf("OPERATOR_GIT_REPO=%s", r.operatorRepo),
		fmt.Sprintf("OPERATOR_BRANCH=%s", r.operatorBranch),
	)
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "get-operator-crds generate check-dirty", env...); err != nil {
		logrus.WithError(err).Error("Failed to check code generation")
		return fmt.Errorf("code generation error, try 'make get-operator-crds generate' to fix")
	}
	return nil
}

func (r *CalicoManager) PreReleaseValidate() error {
	// Check that we are on a release branch
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
		return fmt.Errorf("already on a tag (%s), refusing to create release", out)
	}

	// Check that the repository is not a shallow clone. We need correct history.
	out, err = r.git("rev-parse", "--is-shallow-repository")
	if err != nil {
		return fmt.Errorf("rev-parse failed: %s", err)
	}
	if strings.TrimSpace(out) == "true" {
		return fmt.Errorf("attempt to release from a shallow clone is not possible")
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

	// Assert that release notes are present.
	err = r.assertReleaseNotesPresent(r.calicoVersion)
	if err != nil {
		return err
	}

	return r.releasePrereqs()
}

func (r *CalicoManager) DeleteTag(ver string) error {
	_, err := r.git("tag", "-d", ver)
	if err != nil {
		return fmt.Errorf("failed to delete tag: %s", err)
	}
	return nil
}

func (r *CalicoManager) TagRelease(ver string) error {
	branch, err := r.determineBranch()
	if err != nil {
		return fmt.Errorf("failed to determine branch: %s", err)
	}
	logrus.WithFields(logrus.Fields{"branch": branch, "version": ver}).Infof("Creating Calico release from branch")
	_, err = r.git("tag", ver)
	if err != nil {
		return fmt.Errorf("failed to tag release: %s", err)
	}
	return nil
}

// modifyHelmChartsValues modifies values in helm charts to use the correct version.
// This is only necessary for hashreleases or new branch cut.
func (r *CalicoManager) modifyHelmChartsValues() error {
	operatorChartFilePath := filepath.Join(r.repoRoot, "charts", "tigera-operator", "values.yaml")
	if _, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/version: .*/version: %s/g`, r.operatorVersion), operatorChartFilePath}, nil); err != nil {
		logrus.WithError(err).Errorf("Failed to update operator version in %s", operatorChartFilePath)
		return fmt.Errorf("failed to update operator version in %s: %w", operatorChartFilePath, err)
	}
	if _, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/tag: .*/tag: %s/g`, r.calicoVersion), operatorChartFilePath}, nil); err != nil {
		logrus.WithError(err).Errorf("Failed to update calicoctl version in %s", operatorChartFilePath)
		return fmt.Errorf("failed to update calicoctl version in %s: %w", operatorChartFilePath, err)
	}
	return nil
}

func (r *CalicoManager) resetCharts() {
	if _, err := r.runner.RunInDir(r.repoRoot, "git", []string{"checkout", "charts/"}, nil); err != nil {
		logrus.WithError(err).Error("Failed to reset changes to charts")
	}
}

func (r *CalicoManager) BuildHelm() error {
	if r.isHashRelease {
		if err := r.modifyHelmChartsValues(); err != nil {
			return fmt.Errorf("failed to modify helm chart values: %s", err)
		}
		defer r.resetCharts()
	}

	// Build the helm chart, passing the version to use.
	env := append(os.Environ(),
		fmt.Sprintf("GIT_VERSION=%s", r.calicoVersion),
		fmt.Sprintf("CHART_DESTINATION=%s", r.uploadDir()),
	)
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "chart", env...); err != nil {
		return fmt.Errorf("failed to build helm chart: %w", err)
	}

	// Create helm index for the chart.
	chartURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s", r.githubOrg, r.repo, r.calicoVersion)
	if r.isHashRelease {
		chartURL = r.hashrelease.URL()
	}
	if err := r.buildHelmIndex(r.uploadDir(), chartURL); err != nil {
		return err
	}
	return nil
}

// buildHelmIndex builds the helm index for the given charts directory.
// It downloads the existing helm index, merges in the new chart to create an updated index.
//
// For hashreleases, it copies the helm index to charts/ in the upload directory.
func (r *CalicoManager) buildHelmIndex(chartDir, chartURL string) error {
	// Download existing helm index.
	indexURL, err := url.JoinPath(r.helmRepoURL, helmIndexFileName)
	if err != nil {
		return fmt.Errorf("construct helm index url: %w", err)
	}
	downloadedHelmIndexPath := filepath.Join(r.tmpDir, helmIndexFileName)
	if out, err := r.runner.Run("curl", []string{"-fsSL", "--retry", "3", indexURL, "-o", downloadedHelmIndexPath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("download previous helm index from %s: %w", indexURL, err)
	}

	// Create tmp directory for building index and copy chart there.
	tmpChartsDir := filepath.Join(filepath.Dir(r.uploadDir()), fmt.Sprintf("charts-%s", r.helmChartVersion()))
	if err := os.MkdirAll(tmpChartsDir, utils.DirPerms); err != nil {
		return fmt.Errorf("create temp dir for building helm index: %w", err)
	}

	// Copy charts to temp dir.
	for _, chart := range utils.AllReleaseCharts() {
		srcChart := filepath.Join(chartDir, fmt.Sprintf("%s-%s.tgz", chart, r.helmChartVersion()))
		destChart := filepath.Join(tmpChartsDir, fmt.Sprintf("%s-%s.tgz", chart, r.helmChartVersion()))
		if err := utils.CopyFile(srcChart, destChart); err != nil {
			return fmt.Errorf("error copying %s chart to temp dir for building helm index: %w", chart, err)
		}
	}

	// Build the new helm index.
	args := []string{
		"repo", "index", tmpChartsDir,
		"--url", chartURL,
		"--merge", downloadedHelmIndexPath,
	}
	env := append(os.Environ(), "TZ=UTC")
	if out, err := r.runner.RunInDir(r.repoRoot, "./bin/helm", args, env); err != nil {
		logrus.Error(out)
		return fmt.Errorf("build helm index: %w", err)
	}

	if r.isHashRelease {
		// For hashreleases, copy the helm index to the upload dir.
		srcIndex := filepath.Join(tmpChartsDir, helmIndexFileName)
		destIndex := filepath.Join(r.uploadDir(), "charts", helmIndexFileName)

		// Ensure destination directory exists.
		if err := os.MkdirAll(filepath.Dir(destIndex), utils.DirPerms); err != nil {
			return fmt.Errorf("create dest dir for helm index: %w", err)
		}
		if err := utils.CopyFile(srcIndex, destIndex); err != nil {
			return fmt.Errorf("copy helm index to upload dir: %w", err)
		}
		return nil
	}
	return nil
}

func (r *CalicoManager) buildOCPBundle() error {
	// Build OpenShift bundle.
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "bin/ocp.tgz"); err != nil {
		return fmt.Errorf("failed to build OCP bundle: %w", err)
	}
	return nil
}

func (r *CalicoManager) publishToHashreleaseServer() error {
	if !r.publishHashrelease {
		logrus.Info("Skipping publishing to hashrelease server")
		return nil
	}
	logrus.WithFields(logrus.Fields{
		"version": r.calicoVersion,
		"name":    r.hashrelease.Name,
		"note":    r.hashrelease.Note,
	}).Info("Publishing hashrelease")

	return hashreleaseserver.Publish(r.productCode, &r.hashrelease, &r.hashreleaseConfig)
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

	if r.imageScanning {
		logrus.Info("Sending images to ISS")
		imageScanner := imagescanner.New(r.imageScanningConfig)
		err := imageScanner.Scan(r.productCode, slices.Collect(maps.Values(r.componentImages())), r.hashrelease.Stream, !r.isHashRelease, r.tmpDir)
		if err != nil {
			// Error is logged and ignored as a failure from ISS should not halt the release process.
			logrus.WithError(err).Error("Failed to scan images")
		}
	}

	// Publish helm charts.
	if err := r.publishHelmCharts(); err != nil {
		return fmt.Errorf("failed to publish helm charts: %s", err)
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

		// Update helm chart index
		if err := r.updateHelmChartIndex(); err != nil {
			return fmt.Errorf("update helm chart index: %s", err)
		}
	}

	return nil
}

func (r *CalicoManager) ReleasePublic() error {
	// Get the latest version
	args := []string{
		"release", "list", "--repo", fmt.Sprintf("%s/%s", r.githubOrg, r.repo),
		"--exclude-drafts", "--exclude-prereleases", "--json 'name,isLatest'",
		"--jq '.[] | select(.isLatest) | .name'",
	}
	out, err := r.runner.RunInDir(r.repoRoot, "./bin/gh", args, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest release: %s", err)
	}
	args = []string{
		"release", "edit", r.calicoVersion, "--draft=false",
		"--repo", fmt.Sprintf("%s/%s", r.githubOrg, r.repo),
	}
	latest := version.New(strings.TrimSpace(out))
	current := version.New(r.calicoVersion)
	if current.Semver().GreaterThan(latest.Semver()) {
		args = append(args, "--latest")
	}
	_, err = r.runner.RunInDir(r.repoRoot, "./bin/gh", args, nil)
	if err != nil {
		return fmt.Errorf("failed to publish %s draft release: %s", r.calicoVersion, err)
	}
	return nil
}

// Check general prerequisites for cutting and publishing a release.
func (r *CalicoManager) releasePrereqs() error {
	// Check that we're not on the master branch. We never cut releases from master.
	if branch, err := r.determineBranch(); err != nil {
		return fmt.Errorf("failed to determine branch: %s", err)
	} else if branch == "master" {
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

func (r *CalicoManager) componentImages() map[string]string {
	components := map[string]string{}
	for name, component := range r.imageComponents {
		if component.Registry == "" {
			component.Registry = r.imageRegistries[0]
		}
		components[name] = component.String()
	}
	return components
}

// checkHashreleaseImagesPublished checks that the images required for the hashrelease exist in the specified registries.
func (r *CalicoManager) checkHashreleaseImagesPublished() error {
	logrus.Info("Checking images required for hashrelease have already been published")
	componentImages := r.componentImages()
	numOfComponents := len(componentImages)
	if numOfComponents == 0 {
		logrus.Error("No images to check")
		return fmt.Errorf("no images to check")
	}

	resultsCh := make(chan imageExistsResult, numOfComponents)

	for name, image := range componentImages {
		go func(name string, image string, ch chan imageExistsResult) {
			exists, err := registry.CheckImage(image)
			resultsCh <- imageExistsResult{
				name:   name,
				image:  image,
				exists: exists,
				err:    err,
			}
		}(name, image, resultsCh)
	}

	var resultsErr error
	missingImages := []string{}
	for range componentImages {
		result := <-resultsCh
		if result.err != nil {
			resultsErr = errors.Join(resultsErr, fmt.Errorf("error checking %s: %w", result.image, result.err))
		} else if !result.exists {
			missingImages = append(missingImages, result.image)
		}
	}
	if len(missingImages) > 0 {
		return errors.Join(fmt.Errorf("the following images required for hashrelease have not been published: %s", strings.Join(missingImages, ", ")), resultsErr)
	}
	return resultsErr
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
		if err := r.checkHashreleaseImagesPublished(); err != nil {
			return err
		}
		logrus.Info("All images required for hashrelease have been published")
	}

	return nil
}

// Check that the images exists with the correct version.
func (r *CalicoManager) assertImageVersions() error {
	logrus.Info("Checking built images exists with the correct version")
	buildInfoVersionRegex := regexp.MustCompile(`(?m)^Version:\s+(.*)$`)
	for _, img := range utils.ReleaseImages() {
		switch img {
		case "apiserver":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
				// apiserver always returns an error because there is no kubeconfig, log but do not fail here
				if err != nil {
					logrus.WithError(err).WithField("image", img).Error("error while getting version from apiserver image, continuing")
				}
				if len(buildInfoVersionRegex.FindStringSubmatch(out)) == 0 {
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
		case "cni-windows", "node-windows":
			// Skip windows images
		case "csi", "dikastes", "envoy-gateway", "envoy-proxy", "envoy-ratelimit", "flannel-migration-controller", "goldmane", "node-driver-registrar", "pod2daemon-flexvol", "whisker", "whisker-backend":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "org.opencontainers.image.version" }}'`, fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
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
		case "key-cert-provisioner", "test-signer":
			// key-cert-provisioner images do not have version information.
		case "guardian", "kube-controllers":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "--version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if len(buildInfoVersionRegex.FindStringSubmatch(out)) == 0 {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "node":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "versions"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if len(buildInfoVersionRegex.FindStringSubmatch(out)) == 0 {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "typha":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "calico-typha", "--version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "webhooks":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if !strings.Contains(out, r.calicoVersion) {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
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
	var errStack error
	if r.calicoVersion == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no calico version specified"))
	}
	if r.publishImages && len(r.imageRegistries) == 0 {
		errStack = errors.Join(errStack, fmt.Errorf("no image registries specified"))
	}
	if r.publishCharts {
		if len(r.helmRegistries) == 0 {
			errStack = errors.Join(errStack, fmt.Errorf("no helm chart registries specified"))
		}
		if !r.isHashRelease && r.s3Bucket == "" {
			errStack = errors.Join(errStack, fmt.Errorf("no S3 bucket specified for pushing helm index"))
		}
	}
	if dirty, err := utils.GitIsDirty(r.repoRoot); dirty || err != nil {
		errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before publishing the release"))
	}
	if errStack != nil {
		return errStack
	}
	logrus.WithField("version", r.calicoVersion).Info("Using product version")
	logrus.WithField("registries", r.imageRegistries).Info("Using image registries for publishing")
	if r.isHashRelease {
		return r.hashreleasePrereqs()
	}
	// TODO: Verify all required artifacts are present.
	if err := r.releasePrereqs(); err != nil {
		return err
	}
	return r.assertImageVersions()
}

// Collect artifacts to be included on each release to GitHub.
// It builds the metadata file.
// It assumes that all other artifacts already been built, and simply wraps them up.
//   - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
//   - ocp-vX.Y.Z.tgz: contains the OCP bundle.
//   - tigera-operator-vX.Y.Z.tgz: contains the helm v3 chart.
//   - calico-windows-vX.Y.Z.zip: Calico for Windows zip archive for non-HPC installation.
//   - calicoctl/bin: All calicoctl binaries.
//
// For hashreleases, include the manifests directly.
//
// Finally it generates checksums for each artifact that is uploaded to the release.
func (r *CalicoManager) collectGithubArtifacts() error {
	// Artifacts will be moved here.
	uploadDir := r.uploadDir()

	// Add in a release metadata file.
	err := r.BuildMetadata(uploadDir)
	if err != nil {
		return fmt.Errorf("failed to build release metadata file: %s", err)
	}

	// We attach calicoctl binaries directly to the release as well.
	files, err := os.ReadDir(filepath.Join(r.repoRoot, "calicoctl", "bin"))
	if err != nil {
		return fmt.Errorf("failed to read calicoctl binaries: %w", err)
	}
	for _, b := range files {
		if _, err := r.runner.Run("cp", []string{filepath.Join(r.repoRoot, "calicoctl", "bin", b.Name()), uploadDir}, nil); err != nil {
			return fmt.Errorf("failed to copy calicoctl binary %s: %w", b.Name(), err)
		}
	}

	if r.isHashRelease {
		// Hashrelease include manifests in a different way, instead of just in the release tarball.
		if _, err := r.runner.Run("cp", []string{"-r", filepath.Join(r.repoRoot, "manifests"), uploadDir}, nil); err != nil {
			logrus.WithError(err).Error("Failed to copy manifests to output directory")
			return fmt.Errorf("failed to copy manifests: %w", err)
		}
	}

	// Add in the already-built windows zip archive, the Windows install script, ocp bundle, and the helm chart.
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{fmt.Sprintf("node/dist/calico-windows-%s.zip", r.calicoVersion), uploadDir}, nil); err != nil {
		return fmt.Errorf("failed to copy windows zip archive: %w", err)
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"node/dist/install-calico-windows.ps1", uploadDir}, nil); err != nil {
		return fmt.Errorf("failed to copy windows install script: %w", err)
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"bin/ocp.tgz", uploadDir}, nil); err != nil {
		return fmt.Errorf("failed to copy OCP bundle: %w", err)
	}

	// Generate a SHA256SUMS file containing the checksums for each artifact
	// that we attach to the release. These can be confirmed by end users via the following command:
	// sha256sum -c --ignore-missing SHA256SUMS
	files, err = os.ReadDir(uploadDir)
	if err != nil {
		return fmt.Errorf("failed to read upload directory: %w", err)
	}
	sha256args := []string{}
	for _, f := range files {
		if !f.IsDir() {
			sha256args = append(sha256args, f.Name())
		}
	}
	output, err := r.runner.RunInDir(uploadDir, "sha256sum", sha256args, nil)
	if err != nil {
		return fmt.Errorf("failed to generate sha256sums: %w", err)
	}
	err = os.WriteFile(fmt.Sprintf("%s/SHA256SUMS", uploadDir), []byte(output), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write SHA256SUMS file: %w", err)
	}

	return nil
}

// generateManifests re-generates manifests using the specified calico and operator versions.
func (r *CalicoManager) generateManifests() error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("PRODUCT_VERSION=%s", r.calicoVersion))
	env = append(env, fmt.Sprintf("OPERATOR_VERSION=%s", r.operatorVersion))
	env = append(env, fmt.Sprintf("OPERATOR_REGISTRY_OVERRIDE=%s", r.operatorRegistry))
	env = append(env, fmt.Sprintf("OPERATOR_IMAGE_OVERRIDE=%s", r.operatorImage))
	if !slices.Equal(r.imageRegistries, defaultRegistries) {
		env = append(env, fmt.Sprintf("REGISTRY=%s", r.imageRegistries[0]))
	}
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "gen-manifests", env...); err != nil {
		logrus.WithError(err).Error("Failed to make manifests")
		return fmt.Errorf("failed to generate manifests: %w", err)
	}
	return nil
}

func (r *CalicoManager) resetManifests() {
	if _, err := r.runner.RunInDir(r.repoRoot, "git", []string{"checkout", "manifests", "test-tools/mocknode/mock-node.yaml"}, nil); err != nil {
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
func (r *CalicoManager) buildReleaseTar() error {
	baseReleaseOutputDir := filepath.Dir(r.uploadDir())
	releaseBase := filepath.Join(baseReleaseOutputDir, fmt.Sprintf("release-%s", r.calicoVersion))
	releaseTarFilePath := filepath.Join(baseReleaseOutputDir, fmt.Sprintf("release-%s.tgz", r.calicoVersion))

	if r.archiveImages {
		imgDir := filepath.Join(releaseBase, "images")
		// Create tar files for container image that are shipped.
		err := os.MkdirAll(imgDir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create images dir: %s", err)
		}
		registry := r.imageRegistries[0]
		images := map[string]string{
			fmt.Sprintf("%s/node:%s", registry, r.calicoVersion):                         filepath.Join(imgDir, "calico-node.tar"),
			fmt.Sprintf("%s/typha:%s", registry, r.calicoVersion):                        filepath.Join(imgDir, "calico-typha.tar"),
			fmt.Sprintf("%s/cni:%s", registry, r.calicoVersion):                          filepath.Join(imgDir, "calico-cni.tar"),
			fmt.Sprintf("%s/kube-controllers:%s", registry, r.calicoVersion):             filepath.Join(imgDir, "calico-kube-controllers.tar"),
			fmt.Sprintf("%s/pod2daemon-flexvol:%s", registry, r.calicoVersion):           filepath.Join(imgDir, "calico-pod2daemon.tar"),
			fmt.Sprintf("%s/dikastes:%s", registry, r.calicoVersion):                     filepath.Join(imgDir, "calico-dikastes.tar"),
			fmt.Sprintf("%s/flannel-migration-controller:%s", registry, r.calicoVersion): filepath.Join(imgDir, "calico-flannel-migration-controller.tar"),
		}
		for img, out := range images {
			err = r.archiveContainerImage(out, img)
			if err != nil {
				return fmt.Errorf("failed to archive image %s: %w", img, err)
			}
		}
	}

	// Add in release binaries that we ship.
	binDir := filepath.Join(releaseBase, "bin")
	if err := os.MkdirAll(binDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create images dir: %s", err)
	}

	binaries := map[string]string{
		// CNI plugin binaries
		"cni-plugin/bin/": filepath.Join(binDir, "cni"),

		// Calicoctl binaries.
		"calicoctl/bin/": filepath.Join(binDir, "calicoctl"),

		// Felix binaries.
		"felix/bin/calico-bpf": binDir,
	}
	for src, dst := range binaries {
		if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"-r", src, dst}, nil); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", src, dst, err)
		}
	}

	// Add in manifests directory generated from the docs.
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"-r", "manifests", releaseBase}, nil); err != nil {
		return fmt.Errorf("failed to copy manifests: %w", err)
	}

	// tar up the whole thing, and copy it to the target directory
	if _, err := r.runner.RunInDir(r.repoRoot, "tar", []string{"-czvf", releaseTarFilePath, "-C", baseReleaseOutputDir, fmt.Sprintf("release-%s", r.calicoVersion)}, nil); err != nil {
		return fmt.Errorf("failed to create release tar: %w", err)
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{releaseTarFilePath, r.uploadDir()}, nil); err != nil {
		return fmt.Errorf("failed to copy release tar: %w", err)
	}
	return nil
}

func (r *CalicoManager) buildBinaries() error {
	// Skip building binaries if we are building images
	// binaries are built as part of "release-build" target.
	if r.buildImages {
		return nil
	}
	m := map[string]string{
		"calicoctl":  "build-all",
		"cni-plugin": "build-all",
		"felix":      "release-build",
	}
	env := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", r.calicoVersion),
	)
	for dir, target := range m {
		out, err := r.makeInDirectoryWithOutput(filepath.Join(r.repoRoot, dir), target, env...)
		if err != nil {
			logrus.Error(out)
			return fmt.Errorf("failed to build %s: %w", dir, err)
		}
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
			return fmt.Errorf("failed to build %s: %s", dir, err)
		}
		logrus.Info(out)
		if slices.Contains(windowsReleaseDirs, dir) {
			out, err := r.makeInDirectoryWithOutput(filepath.Join(r.repoRoot, dir), "image-windows", env...)
			if err != nil {
				logrus.Error(out)
				return fmt.Errorf("failed to build %s windows images: %s", dir, err)
			}
			logrus.Info(out)

		}
	}
	return nil
}

func (r *CalicoManager) publishGitTag() error {
	if !r.publishTag {
		logrus.Info("Skipping git tag")
		return nil
	}
	_, err := r.git("push", r.remote, r.calicoVersion)
	if err != nil {
		return fmt.Errorf("failed to push git tag: %w", err)
	}
	return nil
}

func (r *CalicoManager) publishGithubRelease() error {
	if !r.publishGithub {
		logrus.Info("Skipping github release")
		return nil
	}

	releaseNoteTemplate := `
Release notes can be found [on GitHub](https://github.com/projectcalico/calico/blob/{branch}/release-notes/{version}-release-notes.md)

Attached to this release are the following artifacts:

- {release_tar}: container images, binaries, and kubernetes manifests.
- {calico_windows_zip}: Calico for Windows.
- {helm_chart}: Calico Helm 3 chart (also hosted at oci://quay.io/calico/charts/tigera-operator).
- {helm_v1_crd_chart}: Calico crd.projectcalico.org/v1 CRD chart.
- {helm_v3_crd_chart}: Calico projectcalico.org/v3 CRD chart (tech-preview).
- ocp.tgz: Manifest bundle for OpenShift.

Additional links:

- [VPP data plane release information](https://github.com/projectcalico/vpp-dataplane/blob/master/RELEASE_NOTES.md)

`
	ver := version.New(r.calicoVersion)
	sv := ver.Semver()
	formatters := []string{
		// Alternating placeholder / filler. We can't use backticks in the multiline string above,
		// so we replace anything that needs to be backticked into it here.
		"{version}", r.calicoVersion,
		"{branch}", fmt.Sprintf("release-v%d.%d", sv.Major(), sv.Minor()),
		"{release_stream}", fmt.Sprintf("v%d.%d", sv.Major(), sv.Minor()),
		"{release_tar}", fmt.Sprintf("`release-%s.tgz`", r.calicoVersion),
		"{calico_windows_zip}", fmt.Sprintf("`calico-windows-%s.zip`", r.calicoVersion),
		"{helm_chart}", fmt.Sprintf("`%s-%s.tgz`", utils.TigeraOperatorChart, r.calicoVersion),
		"{helm_v1_crd_chart}", fmt.Sprintf("`%s-%s.tgz`", utils.ProjectCalicoV1CRDsChart, r.calicoVersion),
		"{helm_v3_crd_chart}", fmt.Sprintf("`%s-%s.tgz`", utils.ProjectCalicoV3CRDsChart, r.calicoVersion),
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
	_, err := r.runner.RunInDir(r.repoRoot, "./bin/ghr", args, nil)
	if err != nil {
		return fmt.Errorf("failed to publish github release: %w", err)
	}
	return nil
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
				return fmt.Errorf("failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
		if slices.Contains(windowsReleaseDirs, dir) {
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
					return fmt.Errorf("failed to publish %s windows images: %s", dir, err)
				}

				// Success - move on to the next directory.
				logrus.Info(out)
				break
			}
		}
	}
	return nil
}

func (r *CalicoManager) publishHelmCharts() error {
	if !r.publishCharts {
		logrus.Info("Skipping publishing helm charts")
		return nil
	}
	for _, reg := range r.helmRegistries {
		for _, chart := range utils.AllReleaseCharts() {
			if err := r.publishHelmChart(filepath.Join(r.uploadDir(), fmt.Sprintf("%s-%s.tgz", chart, r.helmChartVersion())), reg); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *CalicoManager) publishHelmChart(chart, registry string) error {
	// We allow for a certain number of retries when publishing each chart to a registry, since
	// network flakes can occasionally result in images failing to push.
	maxRetries := 1
	attempt := 0
	args := []string{"push", chart, fmt.Sprintf("oci://%s", registry)}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}
	for {
		out, err := r.runner.RunInDir(r.repoRoot, "./bin/helm", args, nil)
		if err != nil {
			if attempt < maxRetries {
				logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
				attempt++
				continue
			}
			logrus.Error(out)
			return fmt.Errorf("publish %s to %s: %s", chart, registry, err)
		}

		// Success - move on to the next.
		logrus.Info(out)
		break
	}
	return nil
}

func (r *CalicoManager) updateHelmChartIndex() error {
	if !r.publishCharts {
		logrus.Info("Skipping updating helm index")
		return nil
	}
	if err := r.s3Cp(filepath.Join(filepath.Dir(r.uploadDir()), fmt.Sprintf("charts-%s", r.helmChartVersion()), helmIndexFileName), fmt.Sprintf("s3://%s/charts/", r.s3Bucket), s3ACLPublicRead...); err != nil {
		return fmt.Errorf("update helm index: %w", err)
	}
	return nil
}

func (r *CalicoManager) assertReleaseNotesPresent(ver string) error {
	// Validate that the release notes for this version are present,
	// fail if not.
	releaseNotesPath := filepath.Join(r.repoRoot, "release-notes", fmt.Sprintf("%s-release-notes.md", ver))
	releaseNotesStat, err := os.Stat(releaseNotesPath)
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
			return fmt.Errorf("failed to get images from manifest %s: %w", m, err)
		}
		imgs := strings.SplitSeq(out, "\n")
		for i := range imgs {
			if strings.Contains(i, "operator") {
				// We don't handle the operator image here yet, since
				// the version is different.
				continue
			}
			if !strings.HasSuffix(i, ver) {
				return fmt.Errorf("incorrect image version (expected %s) in manifest %s: %s", ver, m, i)
			}
		}
	}

	return nil
}

// determineBranch returns the current checked out branch.
func (r *CalicoManager) determineBranch() (string, error) {
	out, err := r.git("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		logrus.WithError(err).Error("Error determining branch")
		return "", fmt.Errorf("error determining branch: %w", err)
	} else if strings.TrimSpace(out) == "HEAD" {
		logrus.Error("Not on a branch, refusing to cut release")
		return "", fmt.Errorf("not on a branch")
	}
	return strings.TrimSpace(out), nil
}

// Uses docker to build a tgz archive of the specified container image.
func (r *CalicoManager) archiveContainerImage(out, image string) error {
	if r.isHashRelease && !r.buildImages {
		if _, err := r.runner.Run("docker", []string{"image", "inspect", image}, nil); err != nil {
			logrus.WithError(err).WithField("image", image).Error("Image not found locally, will attempt to pull")
			if _, err := r.runner.Run("docker", []string{"pull", image}, nil); err != nil {
				return fmt.Errorf("failed to pull image %s: %w", image, err)
			}
		}
	}
	_, err := r.runner.Run("docker", []string{"save", "--output", out, image}, nil)
	if err != nil {
		return fmt.Errorf("failed to archive image %s: %w", image, err)
	}
	return nil
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

func (r *CalicoManager) s3Cp(src, dest string, additionalFlags ...string) error {
	args := []string{
		"s3", "cp",
		src, dest,
	}
	if r.awsProfile != "" {
		args = append(args, "--profile", r.awsProfile)
	}
	if strings.HasSuffix(src, "/") {
		args = append(args, "--recursive")
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}
	if len(additionalFlags) > 0 {
		args = append(args, additionalFlags...)
	}
	if _, err := r.runner.Run("aws", args, nil); err != nil {
		return err
	}
	return nil
}

func (r *CalicoManager) releaseBranchPrereqs(branch string) error {
	if !r.validate {
		logrus.Warn("Skipping pre-release branch validation")
		return nil
	}
	var errStack error
	if dirty, err := utils.GitIsDirty(r.repoRoot); err != nil {
		errStack = errors.Join(errStack, fmt.Errorf("failed to check if git is dirty: %s", err))
	} else if dirty {
		errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before cutting a release branch"))
	}
	if branch == "" {
		errStack = errors.Join(errStack, fmt.Errorf("release branch not specified"))
	}
	if r.operatorBranch == "" {
		errStack = errors.Join(errStack, fmt.Errorf("operator branch not specified"))
	}
	return errStack
}

// SetupReleaseBranch runs the steps necessary when cutting a new release branch
//
// For a newly created release branch, it will:
//   - Update the versions in the helm charts, metadata.mk.
//   - Run code generation to update generated files based on the new versions.
//   - Commit the changes.
func (r *CalicoManager) SetupReleaseBranch(branch string) error {
	if err := r.releaseBranchPrereqs(branch); err != nil {
		return err
	}

	// Set calico version and operator version to their respective branches for pre-release branch.
	r.calicoVersion = branch
	r.operatorVersion = r.operatorBranch

	// Modify values in charts
	logrus.WithFields(logrus.Fields{
		"calico_version":   r.calicoVersion,
		"operator_version": r.operatorVersion,
	}).Debug("Updating versions in helm charts to release branches")
	calicoChartFilePath := filepath.Join(r.repoRoot, "charts", "calico", "values.yaml")
	if out, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/version: .*/version: %s/g`, branch), calicoChartFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update version in %s: %w", calicoChartFilePath, err)
	}
	if err := r.modifyHelmChartsValues(); err != nil {
		return err
	}

	// Modify values in metadata.mk
	logrus.WithField("operator_branch", r.operatorBranch).Debug("Updating variables in metadata.mk")
	makeMetadataFilePath := filepath.Join(r.repoRoot, "metadata.mk")
	if out, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/^OPERATOR_BRANCH.*/OPERATOR_BRANCH ?= %s/g`, r.operatorBranch), makeMetadataFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update operator branch in %s: %w", makeMetadataFilePath, err)
	}

	// Update release stream used for CAPZ - Windows FV tests.
	releaseStream := strings.TrimPrefix(branch, r.releaseBranchPrefix+"-")
	logrus.WithField("releaseStream", releaseStream).Debug("Updating release stream in setup script for CAPZ Windows FV tests")
	scriptFilePath := filepath.Join(r.repoRoot, "process", "testing", "winfv-felix", "setup-fv-capz.sh")
	if out, err := r.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/RELEASE_STREAM=.*HASH_RELEASE/RELEASE_STREAM=%s HASH_RELEASE/g`, releaseStream), scriptFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update release stream in %s: %w", scriptFilePath, err)
	}

	// Update mocknode test tool to use the correct branch tag.
	logrus.WithField("branch", branch).Debug("Updating mocknode test tool to use the correct branch tag")
	mockNodeFilePath := filepath.Join(r.repoRoot, "test-tools", "mocknode", "mock-node.yaml")
	if out, err := r.runner.Run("sed", []string{"-Ei", fmt.Sprintf(`s#([a-zA-Z .]+)([a-zA-Z.]+/mock-node:)[^[:space:]]+#\1\2%s#g`, branch), mockNodeFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update mocknode image in %s: %w", mockNodeFilePath, err)
	}

	// Run code generation.
	logrus.Debug("Running code generation")
	env := append(os.Environ(), fmt.Sprintf("DEFAULT_BRANCH_OVERRIDE=%s", branch))
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "generate", env...); err != nil {
		return fmt.Errorf("failed to run code generation: %w", err)
	}

	// Commit the changes.
	if out, err := r.git("add",
		filepath.Join(r.repoRoot, ".semaphore"),
		filepath.Join(r.repoRoot, "charts"),
		filepath.Join(r.repoRoot, "manifests"),
		filepath.Join(r.repoRoot, "metadata.mk"),
		filepath.Join(r.repoRoot, "process", "testing", "winfv-felix", "setup-fv-capz.sh"),
		filepath.Join(r.repoRoot, "test-tools", "mocknode"),
	); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to add files to git: %s", err)
	}
	if out, err := r.git("commit", "-m", fmt.Sprintf("Updates for %s release branch", branch)); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to commit changes: %s", err)
	}

	return nil
}
