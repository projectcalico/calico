// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/binaries"
	"github.com/projectcalico/calico/release/internal/branch"
	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/github"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/internal/yamledit"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

// Global configuration for releases.
const (
	binDir       = "bin"
	chartsDir    = "charts"
	manifestsDir = "manifests"
	metadataKey  = "metadata"
)

const calicoctlManifest = "calicoctl.yaml"

var (
	// Default defaultRegistries to which all release images are pushed.
	defaultRegistries = registry.DefaultCalicoRegistries

	defaultOrg    = utils.ProjectCalicoOrg
	defaultRepo   = utils.CalicoRepoName
	defaultBranch = utils.DefaultBranch

	branchTagTarget = "retag-build-images-with-registries push-images-to-registries push-manifests"

	// Windows images are published as a single manifest, so their branch tag
	// is a registry-side copy rather than a retag of local arch images.
	windowsBranchTagTarget = "retag-windows-image-with-registries"
)

func NewManager(opts ...Option) *CalicoManager {
	// Configure defaults here.
	b := &CalicoManager{
		runner:           &command.RealCommandRunner{},
		productCode:      utils.CalicoProductCode,
		validate:         true,
		validateBranch:   true,
		manifests:        true,
		images:           true,
		archiveImages:    true,
		binaries:         true,
		ocpBundle:        true,
		tarball:          true,
		windowsArchive:   true,
		helmCharts:       true,
		helmIndex:        true,
		e2eBinaries:      true,
		dryRun:           false,
		gitRef:           true,
		githubRelease:    true,
		imageRegistries:  defaultRegistries,
		helmRegistries:   registry.DefaultHelmRegistries,
		operatorRegistry: operator.DefaultRegistries[0],
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
	logrus.WithField("repoRoot", b.repoRoot).Info("Using repo root")
	if b.logsDir != "" {
		logrus.WithField("logsDir", b.logsDir).Info("Per-step logs enabled")
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

	// archiveImages controls whether we should archive container images in release tarball.
	archiveImages bool

	// validate is a flag to indicate that we should skip pre-release validation.
	validate bool

	// validateBranch is a flag to indicate that we should skip release branch validation.
	validateBranch bool

	// calicoVersion is the version of calico to release.
	calicoVersion string

	// chartVersion is the version of the helm chart to build.
	chartVersion string

	// operator variables
	operatorImage    string
	operatorRegistry string
	operatorVersion  string

	// imageReleaseDirs limits image building and publishing to these
	// directories. Empty means all of them.
	imageReleaseDirs []string

	resolveDigest steps.DigestResolver

	// outputDir is the directory to which we should write release artifacts, and from
	// which we should read them for publishing.
	outputDir string

	// tmpDir is the directory to which we should write temporary files.
	tmpDir string

	// logsDir is where per-step build/publish logs are written. Each long-running
	// make invocation gets its own file under <logsDir>/<phase>/<component>.log so
	// that timing and failures for an individual component are easy to dig into
	// after a run, and the directory can be uploaded as a CI artifact.
	logsDir string

	dryRun        bool
	gitRef        bool
	githubRelease bool
	draftRelease  bool
	awsProfile    string
	s3Bucket      string
	githubToken   string

	// tagAtHEAD memoizes tagExistsAtHEAD so the rev-parse runs once per release.
	tagAtHEAD *tagCheck

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

	// mainBranch is the default branch for the repo
	// It is also where a new release branch is cut from.
	mainBranch string

	// devTagIdentifier is the suffix used to mark a tag as a development tag.
	devTagIdentifier string

	// releaseBranchPrefix is the prefix for the release branch.
	releaseBranchPrefix string

	// cutOptions holds the branch-cut inputs
	cutOptions branch.CutOptions

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

	// Unified step flags.
	manifests      bool
	images         bool
	binaries       bool
	ocpBundle      bool
	windowsArchive bool
	tarball        bool
	helmCharts     bool
	helmIndex      bool
	e2eBinaries    bool

	retagImages  bool
	fromRegistry string
	fromTag      string
}

func (r *CalicoManager) PreBuildValidation() error {
	var errStack error
	if r.calicoVersion == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no calico version specified"))
	}
	if r.outputDir == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no output directory specified"))
	}

	if r.operatorVersion == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no operator version specified"))
	}
	if (r.images || r.archiveImages) && len(r.imageRegistries) == 0 {
		errStack = errors.Join(errStack, fmt.Errorf("no image registries specified"))
	}
	if r.isHashRelease && r.ocpBundle && !r.manifests {
		errStack = errors.Join(errStack, fmt.Errorf("cannot build OCP bundle without manifests; set --manifests to 'true'"))
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
	var err error
	if r.outputDir == "" {
		return fmt.Errorf("no output directory specified")
	}
	if r.validate {
		if err := r.PreBuildValidation(); err != nil {
			return fmt.Errorf("failed pre-build validation: %s", err)
		}
	}

	// Make sure output directory exists.
	if err = os.MkdirAll(r.uploadDir(), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create output dir: %s", err)
	}

	// Make sure temp directory exists.
	if err = os.MkdirAll(r.tmpDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create temp dir: %s", err)
	}

	if !r.isHashRelease {
		// Only tag release if this is not a hashrelease.
		// TODO: Option to skip producing a tag, for development.
		if err = r.TagRelease(); err != nil {
			return err
		}

		// Successfully tagged. If we fail to release after this stage, we need to delete the tag.
		defer func() {
			if err != nil {
				logrus.WithError(err).Warn("Failed to release, cleaning up tag")
				if err := r.DeleteTag(r.calicoVersion); err != nil {
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

	if err = r.buildManifests(); err != nil {
		return err
	}

	if err = r.buildWindowsArchive(); err != nil {
		return err
	}

	// Build and add in the complete release tarball.
	if err = r.buildReleaseTar(); err != nil {
		return err
	}

	return nil
}

var _ distribution.Attester = metadata{}

type metadata struct {
	Version string `json:"version"`

	OperatorVersion string `json:"operator_version" yaml:"operatorVersion"`

	Images []distribution.Component `json:"images"`

	ChartVersion string `json:"helm_chart_version" yaml:"helmChartVersion"`
}

func (r metadata) Attest() ([]byte, error) {
	var errs []error
	if r.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if r.OperatorVersion == "" {
		errs = append(errs, fmt.Errorf("no operator version specified"))
	}
	if len(r.Images) == 0 {
		errs = append(errs, fmt.Errorf("no images specified"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return yaml.Marshal(r)
}

func (r *CalicoManager) BuildMetadata(dir string) error {
	reg, err := r.getRegistryFromManifests()
	if err != nil {
		return fmt.Errorf("failed to get registry from manifests: %w", err)
	}

	imgs, err := utils.ReleaseImages()
	if err != nil {
		return fmt.Errorf("failed to determine release images: %w", err)
	}
	components := []distribution.Component{
		{Registry: r.operatorRegistry, Image: r.operatorImage, Version: r.operatorVersion},
	}
	for _, img := range imgs {
		components = append(components, distribution.Component{Registry: reg, Image: img, Version: r.calicoVersion})
	}

	return distribution.BuildMetadata(metadata{
		Version:         r.calicoVersion,
		OperatorVersion: r.operatorVersion,
		Images:          components,
		ChartVersion:    r.chart().Version(),
	}, dir, distribution.WithRunner(r.runner))
}

// Fetch the registry from the calicoctl manifest file.
// For hashrelease, it looks in the hashrelease source directory.
func (r *CalicoManager) getRegistryFromManifests() (string, error) {
	key := "spec.containers.image"
	path := filepath.Join(r.repoRoot, manifestsDir, calicoctlManifest)
	if r.isHashRelease {
		p := filepath.Join(r.hashrelease.Source, manifestsDir, calicoctlManifest)
		if _, err := os.Stat(p); err != nil {
			// if the file does not exist, fall back to the default image registry.
			return r.imageRegistries[0], nil
		}
		path = p
	}
	imgs, err := yamledit.Read(path, key)
	if err != nil {
		return "", err
	}
	for _, img := range imgs {
		if !strings.Contains(img, "calico") {
			continue
		}
		// registry/image:tag, so everything before the last slash.
		// A registry may carry a path of its own e.g. example/path/to/image:tag
		if i := strings.LastIndex(img, "/"); i > 0 {
			return img[:i], nil
		}
		return "", nil
	}
	return "", fmt.Errorf("no registry found in %s using key(%s)", path, key)
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
			errStack = errors.Join(errStack, fmt.Errorf("calico checkout is not on a release branch"))
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
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "generate check-dirty"); err != nil {
		logrus.WithError(err).Error("Failed to check code generation")
		return fmt.Errorf("code generation error, try 'make generate' to fix")
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

func (r *CalicoManager) TagRelease() error {
	ver := r.calicoVersion
	branch, err := r.determineBranch()
	if err != nil {
		return fmt.Errorf("failed to determine branch: %w", err)
	}
	logrus.WithFields(logrus.Fields{"branch": branch, "version": ver}).Infof("Creating Calico release from branch")

	tc := r.tagState()
	if tc.err != nil {
		return fmt.Errorf("checking %s tag matches HEAD: %w", ver, tc.err)
	}
	if tc.atHEAD {
		logrus.WithField("version", ver).Info("Tag already exists at HEAD, skipping tag creation")
		return nil
	}

	if _, err = r.git("tag", "-a", "-m", "Release "+ver, ver); err != nil {
		return fmt.Errorf("tag release: %w", err)
	}
	return nil
}

type tagCheck struct {
	atHEAD bool
	err    error
}

// tagState reports whether the release tag already exists and points at HEAD.
// A tag at a different commit is a conflict, surfaced via err.
// The result is memoized as both releasePrereqs and TagRelease consult it.
func (r *CalicoManager) tagState() *tagCheck {
	if r.tagAtHEAD != nil {
		return r.tagAtHEAD
	}
	tc := &tagCheck{}
	tagCommit, err := r.git("rev-parse", "-q", "--verify", "refs/tags/"+r.calicoVersion+"^{commit}")
	if err != nil || strings.TrimSpace(tagCommit) == "" {
		r.tagAtHEAD = tc
		return tc
	}
	tagCommit = strings.TrimSpace(tagCommit)
	headCommit, err := r.git("rev-parse", "HEAD")
	if err != nil {
		tc.err = fmt.Errorf("resolve HEAD: %w", err)
		r.tagAtHEAD = tc
		return tc
	}
	headCommit = strings.TrimSpace(headCommit)
	if tagCommit != headCommit {
		tc.err = fmt.Errorf("tag %s already exists at %s but HEAD is %s", r.calicoVersion, tagCommit, headCommit)
		r.tagAtHEAD = tc
		return tc
	}
	tc.atHEAD = true
	r.tagAtHEAD = tc
	return tc
}

func (r *CalicoManager) BuildHelm() error {
	if !r.helmCharts {
		logrus.Info("Skipping building helm chart and index")
		return nil
	}
	chart := r.chart()
	opts := []charts.BuildOption{charts.WithRunner(r.runner)}
	if r.helmIndex {
		var chartsURL, repoURL string
		var err error
		if r.isHashRelease {
			chartsURL = r.hashrelease.URL()
		} else {
			chartsURL, err = charts.ChartsURL(chart)
			if err != nil {
				return fmt.Errorf("charts URL: %w", err)
			}
		}
		repoURL, err = r.helmRepo()
		if err != nil {
			return fmt.Errorf("helm repo URL: %w", err)
		}
		opts = append(opts, charts.WithIndex(repoURL, chartsURL, chart.BaseDir, r.tmpDir))
	}
	if r.isHashRelease {
		opts = append(opts, charts.WithModifiedValues(charts.ValueEditsFor(r.calicoVersion, r.imageRegistries[0], r.operatorImage, r.operatorVersion, r.operatorRegistry)))
	}
	return charts.Build(chart, opts...)
}

// chart identifies this release's charts to the charts package.
func (r *CalicoManager) chart() charts.Chart {
	return charts.Chart{
		RepoRoot:       r.repoRoot,
		ProductVersion: r.calicoVersion,
		ChartVersion:   r.chartVersion,
		Names:          charts.All(),
		BaseDir:        charts.Dir(r.uploadDir()),
	}
}

// modifyHelmChartsValues rewrites the chart values in the tree.
func (r *CalicoManager) modifyHelmChartsValues() error {
	return charts.ModifyValues(charts.Values{
		RepoRoot: r.repoRoot,
		Edits:    charts.ValueEditsFor(r.calicoVersion, r.imageRegistries[0], r.operatorImage, r.operatorVersion, r.operatorRegistry),
	}, charts.WithRunner(r.runner))
}

// helmRepo is the repository whose index a build merges with.
func (r *CalicoManager) helmRepo() (string, error) {
	if r.helmRepoURL != "" {
		return r.helmRepoURL, nil
	}
	return charts.RepoURL()
}

func (r *CalicoManager) buildOCPBundle() error {
	if !r.ocpBundle {
		logrus.Info("Skipping building OCP bundle")
		return nil
	}
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "bin/ocp.tgz"); err != nil {
		return fmt.Errorf("failed to build OCP bundle: %w", err)
	}
	return r.collectOCPBundle()
}

func (r *CalicoManager) hashreleaseUpload() []distribution.Upload {
	if !r.publishHashrelease {
		logrus.Info("Skipping publishing to hashrelease server")
		return nil
	}

	return []distribution.Upload{{
		Name:   "hashrelease",
		Source: r.uploadDir(),
		Handler: distribution.HashreleaseServer{
			Release:     &r.hashrelease,
			Config:      &r.hashreleaseConfig,
			ProductCode: r.productCode,
			DryRun:      r.dryRun,
			Runner:      r.runner,
		},
	}}
}

func (r *CalicoManager) PublishRelease() error {
	if err := r.publishPrereqs(); err != nil {
		return err
	}
	return distribution.Publish(r.uploads(), distribution.WithRunner(r.runner))
}

func (r *CalicoManager) uploads() []distribution.Upload {
	// The registries go first: metadata records the digests they produce
	uploads := []distribution.Upload{
		{Handler: distribution.Publisher{Kind: "images", Action: r.publishContainerImages}},
		{Handler: distribution.Publisher{Kind: chartsDir, Action: r.publishHelmCharts}},
	}
	uploads = append(uploads,
		distribution.Upload{Handler: distribution.Preparer{Kind: metadataKey, Action: r.buildMetadata}},
		// After metadata, so the sums cover it. Both destinations ship the
		// same directory, so neither can own this.
		distribution.Upload{Handler: distribution.Preparer{Kind: "checksums", Action: r.writeChecksums}},
	)

	if r.isHashRelease {
		return append(uploads, r.hashreleaseUpload()...)
	}
	uploads = append(uploads, r.githubTagUpload())
	github := r.githubReleaseUpload()
	// nil when the github release is disabled.
	if github != nil {
		uploads = append(uploads, *github)
	}
	// Last: the index it writes points at the github release's download URLs,
	// which 404 until that release exists.
	return append(uploads, r.helmIndexUpload())
}

func (r *CalicoManager) buildMetadata() error {
	return r.BuildMetadata(r.uploadDir())
}

// Users verify a download with: sha256sum -c --ignore-missing SHA256SUMS
func (r *CalicoManager) writeChecksums() error {
	return distribution.SHA256Sums(r.uploadDir())
}

// Check general prerequisites for cutting and publishing a release.
func (r *CalicoManager) releasePrereqs() error {
	// Check that we're not on the master branch. We never cut releases from master.
	if branch, err := r.determineBranch(); err != nil {
		return fmt.Errorf("failed to determine branch: %s", err)
	} else if branch == defaultBranch {
		return fmt.Errorf("cannot cut release from branch: %s", branch)
	}

	// If we are releasing to projectcalico/calico, make sure we are releasing to the default registries.
	if r.githubOrg == defaultOrg && r.repo == defaultRepo {
		if !reflect.DeepEqual(r.imageRegistries, defaultRegistries) {
			return fmt.Errorf("image registries cannot be different from default registries for a release")
		}
	}

	// Check if the tag exist and that it does not point at a different commit.
	if tc := r.tagState(); tc.err != nil {
		return fmt.Errorf("checking %s tag matches HEAD: %w", r.calicoVersion, tc.err)
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

	if r.images {
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
	imgs, err := utils.ReleaseImages()
	if err != nil {
		return fmt.Errorf("failed to determine release images: %w", err)
	}
	for _, img := range imgs {
		switch img {
		case "calico":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"run", "--rm", fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion), "version"}, nil)
				if err != nil {
					return fmt.Errorf("failed to run get version from %s image: %s", img, err)
				} else if len(buildInfoVersionRegex.FindStringSubmatch(out)) == 0 {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		case "cni-windows", "node-windows":
			// Skip windows images
		case "third-party-cni-plugins", "envoy-gateway", "envoy-proxy", "envoy-ratelimit", "istio-install-cni", "istio-pilot", "istio-proxyv2", "istio-ztunnel", "whisker":
			for _, reg := range r.imageRegistries {
				out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "org.opencontainers.image.version" }}'`, fmt.Sprintf("%s/%s:%s", reg, img, r.calicoVersion)}, nil)
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
				} else if len(buildInfoVersionRegex.FindStringSubmatch(out)) == 0 {
					return fmt.Errorf("version does not match for image %s/%s:%s", reg, img, r.calicoVersion)
				}
			}
		default:
			return fmt.Errorf("unknown image: %s, update assertion to include validating image", img)
		}
	}
	return r.assertOperatorImageVersion()
}

// assertOperatorImageVersion checks the operator image reports the version it was published at.
// The operator publishes to registries of its own, so it is absent from the release images.
func (r *CalicoManager) assertOperatorImageVersion() error {
	img := fmt.Sprintf("%s/%s:%s", r.operatorRegistry, r.operatorImage, r.operatorVersion)
	out, err := r.runner.Run("docker", []string{"inspect", `--format='{{ index .Config.Labels "org.opencontainers.image.version" }}'`, img}, nil)
	if err != nil {
		return fmt.Errorf("failed to get version from operator image %s: %w", img, err)
	}
	if !strings.Contains(out, r.operatorVersion) {
		return fmt.Errorf("version does not match for image %s", img)
	}
	return nil
}

// Prerequisites specific to publishing a release.
func (r *CalicoManager) publishPrereqs() error {
	// Checked whatever validation is set to: without it the release would write
	// its artifacts somewhere nobody asked for.
	if r.outputDir == "" {
		return fmt.Errorf("no output directory specified")
	}
	if !r.validate {
		logrus.Warn("Skipping pre-publish validation")
		return nil
	}
	var errStack error
	if r.calicoVersion == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no calico version specified"))
	}
	if r.outputDir == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no output directory specified"))
	}
	if r.images && len(r.imageRegistries) == 0 {
		errStack = errors.Join(errStack, fmt.Errorf("no image registries specified"))
	}
	if r.helmCharts {
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

func (r *CalicoManager) collectManifests() error {
	if !r.isHashRelease {
		// Hashrelease include manifests in a different way, instead of just in the release tarball.
		return nil
	}
	if !r.manifests {
		return nil
	}
	uploadDir := r.uploadDir()
	manifestsSrc := filepath.Join(r.repoRoot, manifestsDir) + "/"
	manifestsDest := filepath.Join(uploadDir, manifestsDir) + "/"
	if err := os.MkdirAll(manifestsDest, utils.DirPerms); err != nil {
		return fmt.Errorf("create manifests directory %s: %w", manifestsDest, err)
	}
	rsyncArgs := []string{"-av", "--delete", "--exclude=generate.sh", "--exclude=README.md", "--exclude=.gitattributes"}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		rsyncArgs = append(rsyncArgs, "--verbose", "--progress")
	}
	if _, err := r.runner.Run("rsync", append(rsyncArgs, manifestsSrc, manifestsDest), nil); err != nil {
		logrus.WithError(err).Error("Failed to copy manifests to output directory")
		return fmt.Errorf("failed to copy manifests to output directory: %w", err)
	}
	return nil
}

func (r *CalicoManager) archive() archives.Archive {
	return archives.Archive{
		RepoRoot:        r.repoRoot,
		Version:         r.calicoVersion,
		OperatorVersion: r.operatorVersion,
		OutputDir:       r.uploadDir(),
		Sources:         r.archiveSources(),
	}
}

func (r *CalicoManager) buildWindowsArchive() error {
	if !r.windowsArchive {
		logrus.Info("Skipping building windows archive")
		return nil
	}
	return archives.BuildWindows(
		r.archive(),
		archives.WithRunner(r.runner),
		archives.WithLogsDir(r.logsDir),
	)
}

func (r *CalicoManager) collectOCPBundle() error {
	if !r.ocpBundle {
		return nil
	}
	uploadDir := r.uploadDir()
	if _, err := r.runner.RunInDir(r.repoRoot, "cp", []string{"bin/ocp.tgz", uploadDir}, nil); err != nil {
		return fmt.Errorf("failed to copy OCP bundle: %w", err)
	}
	return nil
}

// buildManifests regenerates manifests for pinned calico/operator versions and
// builds the manifest-derived OCP bundle.
func (r *CalicoManager) buildManifests() error {
	if !r.isHashRelease {
		// regular releases build the OCP bundle directly from the checked-in manifests
		return r.buildOCPBundle()
	}
	if !r.manifests {
		logrus.Info("Skipping regenerating manifests")
		return nil
	}
	defer r.resetManifests()
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
	if err := r.buildOCPBundle(); err != nil {
		return fmt.Errorf("build OCP bundle: %w", err)
	}
	return r.collectManifests()
}

func (r *CalicoManager) resetManifests() {
	if !r.manifests {
		return
	}
	if _, err := r.runner.RunInDir(r.repoRoot, "git", []string{"checkout", manifestsDir, "test-tools/mocknode/mock-node.yaml"}, nil); err != nil {
		logrus.WithError(err).Error("Failed to reset manifests")
	}
}

// Validated before any step runs; see publishPrereqs.
func (r *CalicoManager) uploadDir() string {
	return r.outputDir
}

// TODO: We should produce a tar per architecture that we ship.
// TODO: We should produce windows tars
func (r *CalicoManager) buildReleaseTar() error {
	if !r.tarball {
		logrus.Info("Skipping building release tarball")
		return nil
	}
	return archives.Build(
		r.archive(),
		archives.WithRunner(r.runner),
		archives.WithLogsDir(r.logsDir),
	)
}

func (r *CalicoManager) archiveSources() []archives.Contributor {
	var sources []archives.Contributor
	if r.archiveImages {
		sources = append(sources, images.Archive(r.repoRoot, r.calicoVersion, r.imageReleaseDirs,
			images.WithRunner(r.runner),
			images.WithRegistries(r.imageRegistries...),
			images.WithArches(r.architectures...),
			images.WithPull(r.isHashRelease && !r.images)))
	}
	if r.binaries {
		sources = append(sources, binaries.Archive(r.repoRoot)...)
	}
	if r.manifests {
		root := r.repoRoot
		if r.isHashRelease {
			root = r.hashrelease.Source
		}
		sources = append(sources, archives.DirSource{
			Label: "manifests",
			To:    manifestsDir,
			From:  filepath.Join(root, manifestsDir),
		})
	}
	return sources
}

func (r *CalicoManager) buildBinaries() error {
	var builders []binaries.Builder
	if r.binaries {
		builders = append(builders, binaries.Release(r.uploadDir())...)
	}
	if r.e2eBinaries && r.isHashRelease {
		builders = append(builders, binaries.E2E(r.architectures, binaries.E2EDir(r.uploadDir())))
	}
	if len(builders) == 0 {
		logrus.Info("Skip building binaries")
		return nil
	}
	if err := binaries.Build(r.repoRoot, r.calicoVersion,
		builders,
		binaries.WithRunner(r.runner),
		binaries.WithLogsDir(r.logsDir),
	); err != nil {
		return fmt.Errorf("build binaries: %w", err)
	}
	return nil
}

func (r *CalicoManager) buildContainerImages() error {
	if !r.images {
		logrus.Info("Skip building container images")
		return nil
	}
	err := images.Build(
		r.repoRoot, r.calicoVersion,
		images.NarrowVariants(images.BuildVariants, r.imageReleaseDirs),
		images.WithRunner(r.runner),
		images.WithRegistries(r.imageRegistries...),
		images.WithArches(r.architectures...),
		images.WithLogsDir(r.logsDir),
	)
	if err != nil {
		return fmt.Errorf("build images: %w", err)
	}
	return nil
}

func (r *CalicoManager) publishGitTag() error {
	if !r.gitRef {
		logrus.Info("Skipping git tag")
		return nil
	}

	lsRemote, err := r.git("ls-remote", "--tags", r.remote, "refs/tags/"+r.calicoVersion)
	if err != nil {
		return fmt.Errorf("query remote tag: %w", err)
	}
	if remoteSHA := remoteTagCommit(lsRemote, r.calicoVersion); remoteSHA != "" {
		localSHA, err := r.git("rev-list", "-n1", r.calicoVersion)
		if err != nil {
			return fmt.Errorf("resolve local tag %s: %w", r.calicoVersion, err)
		}
		localSHA = strings.TrimSpace(localSHA)
		if remoteSHA == localSHA {
			logrus.WithField("version", r.calicoVersion).Info("Remote tag already exists and matches, skipping push")
			return nil
		}
		return fmt.Errorf("remote tag %s already exists at %s but local tag is %s", r.calicoVersion, remoteSHA, localSHA)
	}

	args := []string{"push", r.remote, r.calicoVersion}

	if r.dryRun {
		args = append(args, "--dry-run")
	}
	if _, err := r.git(args...); err != nil {
		return fmt.Errorf("failed to push git tag: %w", err)
	}
	return nil
}

// remoteTagCommit returns the commit a remote tag points at.
// For annotated tags, use the peeled reference (refs/tags/<tag>^{}) to get the commit SHA.
func remoteTagCommit(lsRemoteOutput, ver string) string {
	tagRef := "refs/tags/" + ver
	peeledRef := tagRef + "^{}"
	var tagObjSHA, peeledSHA string
	for _, line := range strings.Split(lsRemoteOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[1] {
		case peeledRef:
			peeledSHA = fields[0]
		case tagRef:
			tagObjSHA = fields[0]
		}
	}
	if peeledSHA != "" {
		return peeledSHA
	}
	return tagObjSHA
}

func (r *CalicoManager) githubTagUpload() distribution.Upload {
	return distribution.Upload{Handler: distribution.Preparer{Kind: "git tag", Action: r.publishGitTag}}
}

func (r *CalicoManager) githubReleaseUpload() *distribution.Upload {
	if !r.githubRelease {
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
		"{release_tar}", fmt.Sprintf("`%s`", archives.ArchiveFileName(r.archive())),
		"{calico_windows_zip}", fmt.Sprintf("`%s`", archives.WindowsFileName(r.calicoVersion)),
		"{helm_chart}", fmt.Sprintf("`%s-%s.tgz`", charts.TigeraOperatorChart, r.calicoVersion),
		"{helm_v1_crd_chart}", fmt.Sprintf("`%s-%s.tgz`", charts.ProjectCalicoV1CRDsChart, r.calicoVersion),
		"{helm_v3_crd_chart}", fmt.Sprintf("`%s-%s.tgz`", charts.ProjectCalicoV3CRDsChart, r.calicoVersion),
	}
	replacer := strings.NewReplacer(formatters...)
	releaseNote := replacer.Replace(releaseNoteTemplate)

	return &distribution.Upload{
		Name:   "github release",
		Source: r.uploadDir(),
		Handler: distribution.GithubRelease{
			Repo:   github.Repo{Org: r.githubOrg, Name: r.repo},
			Tag:    r.calicoVersion,
			Body:   releaseNote,
			Draft:  r.draftRelease,
			DryRun: r.dryRun,
		},
	}
}

func (r *CalicoManager) publishContainerImages() error {
	if !r.images {
		logrus.Info("Skipping image publish")
		return nil
	}
	refs, err := outputs.NewRefsWriter(r.outputDir, "images-publish", r.calicoVersion)
	if err != nil {
		return fmt.Errorf("image publish refs writer: %w", err)
	}
	// An earlier run of this version records what it published, so a resume
	// skips the units already done.
	published, err := outputs.ReadRefs(r.outputDir, "images-publish", r.calicoVersion)
	if err != nil {
		return fmt.Errorf("read published image refs: %w", err)
	}
	opts := []images.PublishOption{
		images.WithRunner(r.runner),
		images.WithRegistries(r.imageRegistries...),
		images.WithArches(r.architectures...),
		images.WithLogsDir(r.logsDir),
		images.WithRecord(refs),
	}
	if scan := r.scanRequest(); scan != nil {
		opts = append(opts, images.WithScan(scan))
	}
	if len(published) > 0 {
		opts = append(opts, images.WithResume(published, false))
	}
	if r.retagImages {
		opts = append(opts, images.WithRetag(r.fromRegistry, r.fromTag, !r.gitRef))
	}
	if err := images.Publish(
		r.repoRoot, r.calicoVersion,
		images.NarrowVariants(images.PublishVariants, r.imageReleaseDirs),
		!r.dryRun, r.digestResolver(), opts...,
	); err != nil {
		return fmt.Errorf("publish images: %w", err)
	}
	return r.publishBranchTag()
}

// digestResolver reports a published tag's digest, defaulting to the registry.
// Tests substitute one so they never reach the network.
func (r *CalicoManager) digestResolver() steps.DigestResolver {
	if r.resolveDigest != nil {
		return r.resolveDigest
	}
	return registry.ResolveDigest
}

// The images come from the pinned components, so a hashrelease scans what it
// pinned.
func (r *CalicoManager) scanRequest() *images.ScanRequest {
	if !r.imageScanning {
		return nil
	}
	ver := version.Version(r.calicoVersion)
	return &images.ScanRequest{
		Config:      r.imageScanningConfig,
		ProductCode: r.productCode,
		Images:      slices.Collect(maps.Values(r.componentImages())),
		Stream:      ver.PrimaryStream(),
		Release:     !r.isHashRelease,
		OutputDir:   r.tmpDir,
	}
}

var releaseBranch = func(r *CalicoManager) (string, error) {
	if r.releaseBranchPrefix == "" {
		return "", fmt.Errorf("release branch prefix is not set")
	}
	ver := version.Version(r.calicoVersion)
	return fmt.Sprintf("%s-%s", r.releaseBranchPrefix, ver.Stream()), nil
}

// publishBranchTag moves the branch-named tag (e.g. release-v3.33) onto the
// images just published, so the branch always has a pullable tag between
// official releases.
func (r *CalicoManager) publishBranchTag() error {
	branch, err := releaseBranch(r)
	if err != nil {
		return fmt.Errorf("release branch: %w", err)
	}
	if branch == "" {
		return nil
	}
	registry, err := r.getRegistryFromManifests()
	if err != nil {
		return fmt.Errorf("get registry from manifests: %w", err)
	}
	// The arch images must carry the branch tag before the manifest can list
	// them as its children.
	if err := images.Publish(
		r.repoRoot, branch,
		images.NarrowVariants([]images.Variant{
			{
				Name:        images.StandardVariant,
				Target:      branchTagTarget,
				ReleaseDirs: images.VariantDirs(images.StandardVariants(images.PublishVariants)),
			},
			{
				Name:        images.WindowsVariant,
				Target:      windowsBranchTagTarget,
				ReleaseDirs: slices.Clone(utils.WindowsReleaseDirs),
			},
		}, r.imageReleaseDirs),
		!r.dryRun, r.digestResolver(),
		images.WithRunner(r.runner),
		images.WithRegistries(registry),
		images.WithArches(r.architectures...),
		images.WithLogsDir(r.logsDir),
		images.WithStepName("images-publish-branch"),
		images.WithRetag(r.imageRegistries[0], r.calicoVersion, true),
	); err != nil {
		return fmt.Errorf("publish branch %s tag images: %w", branch, err)
	}

	// The operator publishes to its own registries, so it takes a pass of its own.
	if err := images.Publish(
		r.repoRoot, branch,
		[]images.Variant{{
			Name:        images.StandardVariant,
			Target:      branchTagTarget,
			ReleaseDirs: []string{utils.OperatorDir},
		}},
		!r.dryRun, r.digestResolver(),
		images.WithRunner(r.runner),
		images.WithRegistries(operator.DefaultRegistries...),
		images.WithArches(r.architectures...),
		images.WithLogsDir(r.logsDir),
		images.WithStepName("images-publish-branch-operator"),
		images.WithRetag(operator.DefaultRegistries[0], r.calicoVersion, true),
	); err != nil {
		return fmt.Errorf("publish branch %s tag operator image: %w", branch, err)
	}
	return nil
}

func (r *CalicoManager) publishHelmCharts() error {
	if !r.helmCharts {
		logrus.Info("Skipping publishing helm charts")
		return nil
	}
	chart := r.chart()
	refs, err := outputs.NewRefsWriter(r.outputDir, charts.PublishStep, chart.Version())
	if err != nil {
		return fmt.Errorf("chart publish refs writer: %w", err)
	}
	// An earlier run of this version records what it published, so a resume
	// skips the charts already done.
	published, err := outputs.ReadRefs(r.outputDir, charts.PublishStep, chart.Version())
	if err != nil {
		return fmt.Errorf("read published chart refs: %w", err)
	}
	opts := []charts.PublishOption{
		charts.WithRunner(r.runner),
		charts.WithLogsDir(r.logsDir),
		charts.WithResolver(r.digestResolver()),
		charts.WithRecord(refs),
	}
	if len(published) > 0 {
		opts = append(opts, charts.WithResume(published, false))
	}
	return charts.Publish(chart, r.helmRegistries, !r.dryRun, opts...)
}

func (r *CalicoManager) helmIndexUpload() distribution.Upload {
	return distribution.Upload{
		Name:   "chart index",
		Source: charts.IndexFilePath(r.chart().BaseDir),
		Skip:   !r.helmCharts || !r.helmIndex,
		Handler: distribution.S3{
			URI:     r.s3URI(chartsDir),
			Profile: r.awsProfile,
			DryRun:  r.dryRun,
			Runner:  r.runner,
		},
	}
}

func (r *CalicoManager) s3URI(path ...string) string {
	return fmt.Sprintf("s3://%s/%s/", r.s3Bucket, strings.Join(path, "/"))
}

func (r *CalicoManager) assertReleaseNotesPresent(ver string) error {
	// Validate that the release notes for this version are present,
	// fail if not.
	releaseNotesPath := outputs.ReleaseNoteFilePath(r.repoRoot, ver)
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
		out, err := r.runner.RunInDir(filepath.Join(r.repoRoot, manifestsDir), "grep", args, nil)
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

func (r *CalicoManager) releaseBranchPrereqs() error {
	// cutOptions is required for the branch cut flow
	if r.cutOptions == nil {
		return fmt.Errorf("cut options not specified")
	}
	if !r.validate {
		logrus.Warn("Skipping pre-release branch validation")
		return nil
	}
	return nil
}

// branchChangedPaths are the trees the prepareDerived hook rewrites; it reports
// them so the branch flow stages them into the cut commit.
var branchChangedPaths = []string{
	chartsDir,
	manifestsDir,
	".semaphore",
	"test-tools/mocknode",
}

// CutBranch cuts the release branch off main and advances main to the next
// dev line.
func (r *CalicoManager) CutBranch() error {
	if err := r.releaseBranchPrereqs(); err != nil {
		return err
	}
	d := &branch.Driver{
		RepoRoot:            r.repoRoot,
		Remote:              r.remote,
		MainBranch:          r.mainBranch,
		DevTagIdentifier:    r.devTagIdentifier,
		ReleaseBranchPrefix: r.releaseBranchPrefix,
		Validate:            r.validate,
		Publish:             r.gitRef,
		Plan:                r.cutOptions.OnlyPlan(),
		BranchCheck:         r.cutOptions.CheckBranch(),
		Skip:                r.cutOptions.SkipSteps(),
		PrepareDerived:      r.prepareDerived,
	}
	plan, err := r.cutPlan()
	if err != nil {
		return err
	}
	if err := r.requireOnMainBranch(plan.Derived); err != nil {
		return err
	}
	return d.CutReleaseBranch(plan)
}

// CutOptions is a branch.CutOptions implementation.
type CutOptions struct {
	Plan        bool
	Skip        map[string]bool
	BranchCheck bool
}

func (o CutOptions) OnlyPlan() bool             { return o.Plan }
func (o CutOptions) SkipSteps() map[string]bool { return o.Skip }
func (o CutOptions) CheckBranch() bool          { return o.BranchCheck }

// requireOnMainBranch rejects a cut run off the main branch, since the cut
// always derives from main regardless of the checkout.
func (r *CalicoManager) requireOnMainBranch(derived string) error {
	if !r.validate {
		logrus.Warn("Skipping main branch validation")
		return nil
	}
	if exists, err := command.GitInDir(r.repoRoot, "rev-parse", "--verify", "--quiet", "refs/heads/"+derived); err == nil && strings.TrimSpace(exists) != "" {
		return nil // resume: the derived branch already exists
	}
	out, err := command.GitInDir(r.repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("determining current branch: %w", err)
	}
	if cur := strings.TrimSpace(out); cur != r.mainBranch {
		return fmt.Errorf("branch cut must run on %s, but the current branch is %s", r.mainBranch, cur)
	}
	return nil
}

// cutPlan builds the plan: a release-vX.Y branch off main. Only main gets a new
// tag (next minor); the branch inherits main's tag via the shared commit.
func (r *CalicoManager) cutPlan() (*branch.CutPlan, error) {
	// Read the version from main, not HEAD: the branch is cut from main and its
	// name and tags must derive from main's commit.
	mainVersion, err := command.GitInDir(r.repoRoot, "describe", "--tags", "--abbrev=0", r.mainBranch)
	if err != nil {
		return nil, fmt.Errorf("determining %s version: %w", r.mainBranch, err)
	}
	cur := version.New(strings.TrimSpace(mainVersion))
	nextBranch := cur.NextBranchVersion()
	derived := r.releaseBranchPrefix + "-" + cur.Stream()
	return &branch.CutPlan{
		Derived: derived,
		Source:  r.mainBranch,
		Remote:  r.remote,
		TagTargets: []branch.TagTarget{
			{Branch: r.mainBranch, DevTag: nextBranch.FormattedString() + "-" + r.devTagIdentifier},
		},
	}, nil
}

// derivedBranchEdits returns the edits to make in the freshly-cut-branch.
func derivedBranchEdits(derived, stream string) []branch.Edit {
	return []branch.Edit{
		{File: "test-tools/mocknode/mock-node.yaml", Pattern: `([a-zA-Z .]+)([a-zA-Z.]+/mock-node:)[^[:space:]]+`, Replacement: fmt.Sprintf(`${1}${2}%s`, derived)},
		{File: "process/testing/aso/export-env.sh", Pattern: `export RELEASE_STREAM="\$\{RELEASE_STREAM:=master\}"`, Replacement: fmt.Sprintf(`export RELEASE_STREAM="${RELEASE_STREAM:=%s}"`, stream)},
		{File: "process/testing/aso/install-calico.sh", Pattern: `: \$\{RELEASE_STREAM:="master"\} # Default to master`, Replacement: fmt.Sprintf(`: ${RELEASE_STREAM:="%s"} # Default to %s`, stream, stream)},
	}
}

// prepareDerived is the PrepareDerived hook: on a fresh branch it applies the
// edits, rewrites helm values, and runs code generation, returning changed files.
func (r *CalicoManager) prepareDerived(derived string) ([]string, error) {
	stream := strings.TrimPrefix(derived, r.releaseBranchPrefix+"-")
	written, _, err := branch.ApplyEdits(r.repoRoot, derivedBranchEdits(derived, stream))
	if err != nil {
		return nil, err
	}

	// The operator ships on Calico's version stream, so a pre-release branch
	// pins both to the derived branch.
	r.calicoVersion = derived
	r.operatorVersion = derived

	logrus.WithFields(logrus.Fields{
		"calico_version":   r.calicoVersion,
		"operator_version": r.operatorVersion,
	}).Debug("Updating versions in helm charts to release branches")
	if err := r.modifyHelmChartsValues(); err != nil {
		return nil, err
	}

	logrus.Debug("Running code generation")
	env := append(os.Environ(), fmt.Sprintf("DEFAULT_BRANCH_OVERRIDE=%s", derived))
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "generate", env...); err != nil {
		return nil, fmt.Errorf("failed to run code generation: %w", err)
	}

	// The helm and generate steps rewrite these tracked trees; stage them alongside
	// the edit-written files.
	changed := append(written, branchChangedPaths...)
	return changed, nil
}

func (r *CalicoManager) prepareReleaseCleanup(baseBranch, prepBranch string) {
	curr, err := r.determineBranch()
	if err != nil {
		logrus.WithError(err).Error("Failed to determine current branch during cleanup")
		return
	}
	if curr == baseBranch {
		return
	}
	if curr == prepBranch {
		logrus.Warnf("An error occurred while preparing the %s release, investigate the issue and fix if necessary.\nTo re-run the release preparation, use the following command:\n\n\tgit switch -f %s", prepBranch, baseBranch)
		return
	}
	logrus.WithField("branch", curr).Warn("Unexpected branch during release preparation cleanup, expected to be on base or prep branch")
}

// PrepareRelease performs release preparation for Calico.
// It validates the repo state, creates a build branch, updates version references
// in charts and manifests, and commits the changes.
// If publishTag is true, the branch is pushed to the remote.
func (r *CalicoManager) PrepareRelease() (string, error) {
	if err := r.prepPrereqs(); err != nil {
		return "", err
	}

	ver := version.New(r.calicoVersion)
	baseBranch, err := r.determineBranch()
	if err != nil {
		logrus.WithError(err).Error("Failed to determine current branch, will use default branch for release preparation")
		baseBranch = fmt.Sprintf("%s-%s", r.releaseBranchPrefix, ver.Stream())
		logrus.WithField("baseBranch", baseBranch).Info("Using default branch for release preparation")
	}
	prepBranch := fmt.Sprintf("build-%s", ver)

	defer r.prepareReleaseCleanup(baseBranch, prepBranch)

	if err := r.switchToPrepBranch(prepBranch); err != nil {
		return "", err
	}

	if err := r.updateAndCommitPrep(); err != nil {
		return "", err
	}

	return prepBranch, r.pushPrepBranch(baseBranch, prepBranch)
}

// switchToPrepBranch records the current branch for cleanup, then creates
// and switches to the prep branch. Safe to re-run (force-creates).
func (r *CalicoManager) switchToPrepBranch(prepBranch string) error {
	if out, err := r.git("switch", "-C", prepBranch); err != nil {
		logrus.Error(out)
		return fmt.Errorf("create branch %s: %w", prepBranch, err)
	}
	return nil
}

// updateAndCommitPrep updates charts and manifests, then stages and commits.
func (r *CalicoManager) updateAndCommitPrep() error {
	if err := r.modifyHelmChartsValues(); err != nil {
		return fmt.Errorf("failed to update chart versions: %w", err)
	}
	if err := r.makeInDirectoryIgnoreOutput(r.repoRoot, "generate"); err != nil {
		return fmt.Errorf("failed to run make generate: %w", err)
	}

	if _, err := r.git("add",
		filepath.Join(r.repoRoot, chartsDir),
		filepath.Join(r.repoRoot, manifestsDir),
		filepath.Join(r.repoRoot, outputs.ReleaseNotesDir),
	); err != nil {
		return fmt.Errorf("failed to stage files: %w", err)
	}
	if _, err := r.git("commit", "-m", fmt.Sprintf("build: %s release", r.calicoVersion)); err != nil {
		return fmt.Errorf("failed to commit changes: %w", err)
	}
	return nil
}

// pushPrepBranch pushes the prep branch to remote and creates a PR if not in local mode.
func (r *CalicoManager) pushPrepBranch(baseBranch, prepBranch string) error {
	if !r.gitRef {
		logrus.WithField("branch", prepBranch).Warn("Local mode: skipping branch push and PR creation")
		return r.switchToBaseBranch(baseBranch)
	}

	if _, err := r.git("push", "--force-with-lease", r.remote, prepBranch); err != nil {
		return fmt.Errorf("failed to push %q branch: %w", prepBranch, err)
	}
	logrus.WithField("branch", prepBranch).Info("Pushed preparation branch to remote")

	return r.createPrepPR(baseBranch, prepBranch)
}

// createPrepPR creates a pull request for the prep branch.
func (r *CalicoManager) createPrepPR(baseBranch, prepBranch string) error {
	args := []string{
		"pr", "create", "--fill",
		"--repo", fmt.Sprintf("%s/%s", r.githubOrg, r.repo),
		"--base", baseBranch,
		"--head", prepBranch,
	}
	if r.githubOrg == defaultOrg && r.repo == defaultRepo {
		args = append(args, []string{
			"--reviewer", fmt.Sprintf("%s/release-team", r.githubOrg),
			"--label", "release-note-not-required,docs-not-required",
		}...)
	}
	fallbackURL := fmt.Sprintf("https://github.com/%s/%s/pulls?q=is%%3Aopen+head%%3A%s", r.githubOrg, r.repo, prepBranch)
	logrus.WithField("args", args).Debug("Creating PR for release preparation")
	pr, err := r.runner.RunInDir(r.repoRoot, "./bin/gh", args, nil)
	if err != nil {
		pr = fallbackURL
		if strings.Contains(err.Error(), "already exists") {
			if m := regexp.MustCompile(`(?:^|\s)(https://github\.com/[\w.-]+/[\w.-]+/pull/\d+)(?:$|\s)`).FindStringSubmatch(err.Error()); len(m) > 1 {
				if u, err := url.Parse(m[1]); err != nil {
					logrus.WithField("PR", pr).Warn("PR already exists but could not parse URL from error, find using fallback PR URL")
					return fmt.Errorf("parsing URL for PR: %w", err)
				} else if u.Host != "github.com" || !strings.Contains(m[1], fmt.Sprintf("%s/%s/pull/", r.githubOrg, r.repo)) {
					logrus.WithField("PR", pr).Warn("PR already exists but error returned an unexpected URL, find using fallback PR URL")
					return fmt.Errorf("unexpected URL format for PR: %s", m[1])
				}
				pr = m[1]
			}
			logrus.WithField("PR", pr).Warn("PR already exists, skipping creation")
			return r.switchToBaseBranch(baseBranch)
		}
		logrus.WithError(err).Error("Failed to create PR for release preparation")
		return fmt.Errorf("failed to create PR: %s", err)
	}
	logrus.WithField("PR", strings.TrimSpace(pr)).Info("Created PR for release preparation")
	return r.switchToBaseBranch(baseBranch)
}

func (r *CalicoManager) switchToBaseBranch(baseBranch string) error {
	if out, err := r.git("switch", "-f", baseBranch); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to switch back to base branch %s: %w", baseBranch, err)
	}
	return nil
}

// prepPrereqs validates that the repo is in a suitable state for release preparation.
func (r *CalicoManager) prepPrereqs() error {
	if !r.validate {
		logrus.Warn("Skipping release preparation validation")
		return nil
	}

	// Check that the git repo is clean.
	if dirty, err := utils.GitIsDirty(r.repoRoot); err != nil {
		return fmt.Errorf("failed to check if git repo is clean: %w", err)
	} else if dirty {
		return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before preparing the release")
	}

	// Check that we're not on the default branch (master). We never prep releases from the default branch.
	if r.validateBranch {
		if branch, err := r.determineBranch(); err != nil {
			return fmt.Errorf("failed to determine current git branch: %w", err)
		} else if branch == defaultBranch {
			return fmt.Errorf("cannot cut release from branch: %s", branch)
		} else if r.gitRef && !strings.HasPrefix(branch, r.releaseBranchPrefix) {
			return fmt.Errorf("current branch is %s, expected to be a release branch with prefix %s. Please switch to the appropriate release branch to cut the release", branch, r.releaseBranchPrefix)
		}
	}

	// If publishing, check that we are not on a fork branch. We want to ensure releases are always cut from the main repo
	if r.gitRef {
		owner, err := r.remoteOwner()
		if err != nil {
			return err
		}
		if owner != r.githubOrg {
			return fmt.Errorf("current git remote is %s, expected to be from %s. Please switch to a branch from the main repo to cut the release", owner, r.githubOrg)
		}
	}

	// Check that the release notes are present for this version.
	if err := r.assertReleaseNotesPresent(r.calicoVersion); err != nil {
		return err
	}

	// Check that the versions are release version.
	versionRegex := regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
	if !versionRegex.MatchString(r.operatorVersion) {
		return fmt.Errorf("operator version (%s) is not a release version", r.operatorVersion)
	}
	versionRegex = regexp.MustCompile(`^v\d+\.\d+\.\d+(-\d+\.\d+)?$`)
	if !versionRegex.MatchString(r.calicoVersion) {
		return fmt.Errorf("version (%s) is not a release version", r.calicoVersion)
	}

	return nil
}

// remoteOwner extracts the GitHub owner (org or user) from the configured git remote URL.
func (r *CalicoManager) remoteOwner() (string, error) {
	out, err := r.git("config", "--get", fmt.Sprintf("remote.%s.url", r.remote))
	if err != nil {
		return "", fmt.Errorf("failed to get remote %s url: %w", r.remote, err)
	}
	return ownerFromRemoteURL(strings.TrimSpace(out))
}

// ownerFromRemoteURL extracts the GitHub owner (org or user) from a git remote URL.
// Supports SSH (git@github.com:owner/repo.git),
// HTTPS (https://github.com/owner/repo.git), and variants without .git suffix.
func ownerFromRemoteURL(raw string) (string, error) {
	raw = strings.TrimSuffix(raw, ".git")

	// SSH: git@github.com:owner/repo
	if i := strings.Index(raw, ":"); i >= 0 && !strings.Contains(raw[:i], "/") {
		parts := strings.Split(raw[i+1:], "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2], nil
		}
		return "", fmt.Errorf("unable to determine owner from remote URL %q", raw)
	}

	// HTTPS: https://github.com/owner/repo — require scheme prefix.
	if strings.Contains(raw, "://") {
		parts := strings.Split(raw, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2], nil
		}
	}

	return "", fmt.Errorf("unable to determine owner from remote URL %q", raw)
}
