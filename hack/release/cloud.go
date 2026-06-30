// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// This file is part of the single release tool binary. Its Calico Cloud behavior is activated at
// runtime only when VARIANT=cloud (see cloudVariantEnabled): init() then reassigns the shared release
// tool's package-level hooks (isValidReleaseVersion, setupHashreleaseBuild, publishImages, command
// Before funcs) and registers the cloud flags. When VARIANT is unset, init() returns immediately and
// the regular Calico / Calico Enterprise release tool is completely unaffected. This replaces the
// former `-tags cloud` build so one binary handles both (per PR review from @radTuti / @caseydavenport).

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"

	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/middleware"
	"github.com/tigera/operator/hack/release/internal/versions"
)

const (
	// Regex pattern for validating cloud release versions (e.g. cloud-v3.22.1-0 or cloud-v3.22.0-3.0-4).
	cloudReleaseFormat = `^cloud-v\d+\.\d+\.\d+-[-.\d]+$`

	// Default registry and image for cloud releases.
	gcrRegistry       = "gcr.io"
	cloudDevImage     = "tigera-cc-dev/operator-cloud"
	cloudReleaseImage = "tigera-tesla/operator-cloud"

	// Hashrelease variables.
	gitHashLength            = 9
	managerComponentName     = "manager"
	pinnedComponentsFileName = "pinned_components.yml"

	// Output path and files for Argo workflow (build-hashrelease).
	outputsDir                = "/tmp/"
	imageTagFileName          = "image-tag"
	hashreleaseStatusFileName = "new-hashrelease"
)

// checkOneOfFlagsSet checks that at most one of the specified flags is set in the command.
func checkOneOfFlagsSet(c *cli.Command, flagNames ...string) error {
	setFlags := []string{}
	for _, name := range flagNames {
		if c.IsSet(name) {
			setFlags = append(setFlags, name)
		}
	}
	if len(setFlags) > 1 {
		return fmt.Errorf("only one of the following flags can be set: %s", strings.Join(flagNames, ", "))
	}
	return nil
}

// Cloud-specific flags
var (
	cloudFlagCategory      = "Cloud Options"
	hashreleaseURLFlagName = "hashrelease-url"
	hashreleaseURLFlag     = &cli.StringFlag{
		Name:     hashreleaseURLFlagName,
		Category: cloudFlagCategory,
		Usage:    "URL to the hashrelease server hosting pinned_components.yml (e.g. https://2023-09-12-v3-18-turkey.docs.eng.tigera.net)",
		Sources:  cli.EnvVars("HASHRELEASE_URL"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("hashrelease-url can only be set for hashreleases")
			}
			return checkOneOfFlagsSet(c, hashreleaseURLFlagName, pinnedComponentsFileFlagName)
		},
	}
	pinnedComponentsFileFlagName = "pinned-components"
	pinnedComponentsFileFlag     = &cli.StringFlag{
		Name:     pinnedComponentsFileFlagName,
		Category: cloudFlagCategory,
		Usage:    "Local path to a pinned_components.yml file (alternative to downloading from URL)",
		Sources:  cli.EnvVars("PINNED_COMPONENTS_FILE"),
		Action: func(ctx context.Context, c *cli.Command, s string) error {
			if s != "" && !c.Bool(hashreleaseFlag.Name) {
				return fmt.Errorf("pinned-components can only be set for hashreleases")
			}
			if err := checkOneOfFlagsSet(c, hashreleaseURLFlagName, pinnedComponentsFileFlagName); err != nil {
				return err
			}
			return fileFlagCheck(ctx, c, s)
		},
	}
	cloudRegistryFlag = &cli.StringFlag{
		Name:     "cloud-registry",
		Category: cloudFlagCategory,
		Usage:    "The registry Cloud images are hosted in",
		Sources:  cli.EnvVars("CLOUD_REGISTRY"),
	}
)

// cloudVariantEnabled reports whether the release tool is running as the Calico Cloud variant. It is
// driven by the VARIANT env var (set by `make ... VARIANT=cloud`), so a single release binary serves
// both the enterprise and cloud release flows.
func cloudVariantEnabled() bool {
	return os.Getenv("VARIANT") == "cloud"
}

func init() {
	// Cloud behavior is opt-in at runtime; leave the OSS/enterprise release tool untouched otherwise.
	if !cloudVariantEnabled() {
		return
	}

	// Override version validation for cloud releases.
	isValidReleaseVersion = isCloudReleaseVersionFormat

	// Update default registry and image for cloud releases.
	defaultRegistry = gcrRegistry
	defaultImage = cloudReleaseImage

	// Update OSS flags default for cloud.
	// Flag structs capture their Value at var-init time (before init runs),
	// so we must also update the flag defaults to match the cloud values.
	registryFlag.Value = gcrRegistry
	imageFlag.Value = cloudReleaseImage
	versionFlag.Required = false // hashrelease versions are generated, not manually set
	createGithubReleaseFlag.Value = false

	// Register cloud-specific build flags.
	buildCommand.Flags = append(buildCommand.Flags,
		hashreleaseURLFlag,
		pinnedComponentsFileFlag,
		cloudRegistryFlag,
	)

	// Register cloud-specific publish flags.
	publishCommand.Flags = append(publishCommand.Flags,
		hashreleaseURLFlag,
		pinnedComponentsFileFlag,
	)

	// Wrap build command to run cloud-specific pre-processing before the OSS logic.
	ossBuildBefore := buildCommand.Before
	buildCommand.Before = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
		middleware.ConfigureLogging(c)
		if err := cloudBuildBefore(ctx, c); err != nil {
			return ctx, fmt.Errorf("cloud build before: %w", err)
		}
		return ossBuildBefore(ctx, c)
	})

	// Wrap hashrelease setup to perform cloud-specific setup before the OSS logic.
	ossSetupHashreleaseBuild := setupHashreleaseBuild
	setupHashreleaseBuild = func(ctx context.Context, c *cli.Command, repoRootDir string) error {
		if err := cloudSetupHashreleaseBuild(ctx, c, repoRootDir); err != nil {
			return err
		}
		return ossSetupHashreleaseBuild(ctx, c, repoRootDir)
	}

	// Wrap publish command to run cloud-specific pre-processing before the OSS logic.
	ossPublishBefore := publishCommand.Before
	publishCommand.Before = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
		middleware.ConfigureLogging(c)
		if err := cloudPublishBefore(ctx, c); err != nil {
			return ctx, fmt.Errorf("cloud publish before: %w", err)
		}
		return ossPublishBefore(ctx, c)
	})

	// Wrap publishImages to write CI output files after publishing.
	ossPublishImages := publishImages
	publishImages = func(c *cli.Command, repoRootDir string) error {
		// Check before publishing to determine if this will be a new release.
		alreadyPublished, _ := operatorImagePublished(c)
		if err := ossPublishImages(c, repoRootDir); err != nil {
			return err
		}
		if err := cloudPostPublish(c, !alreadyPublished); err != nil {
			// Post-publish errors are non-fatal — images are already published.
			logrus.WithError(err).Warn("Cloud post-publish failed (continuing as images are published)")
		}
		return nil
	}
}

// isCloudReleaseVersionFormat checks if the version is in the format cloud-vX.Y.Z-S,
// where S is a suffix composed of digits, dots, and hyphens (e.g. cloud-v3.22.1-0 or cloud-v3.22.0-3.0-4).
func isCloudReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(cloudReleaseFormat)
	if err != nil {
		return false, fmt.Errorf("compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

// pinnedComponentsFile returns the path to the pinned components file, either from a local file or downloaded from a URL.
func pinnedComponentsFile(ctx context.Context, c *cli.Command) (string, error) {
	if pinnedFile := c.String(pinnedComponentsFileFlag.Name); pinnedFile != "" {
		logrus.WithField("file", pinnedFile).Info("Using pinned components from file")
		return pinnedFile, nil
	}
	hashreleaseURL := c.String(hashreleaseURLFlag.Name)
	if hashreleaseURL == "" {
		return "", fmt.Errorf("either the hashrelease URL (via --%s flag or environment variable) "+
			"or the pinned components file (via --%s flag or environment variable) must be set", hashreleaseURLFlag.Name, pinnedComponentsFileFlag.Name)
	}
	// Download the pinned components to a temp file and return the path.
	pinnedURL, err := url.JoinPath(hashreleaseURL, pinnedComponentsFileName)
	if err != nil {
		return "", fmt.Errorf("constructing path to pinned component for hashrelease: %w", err)
	}
	logrus.WithField("url", pinnedURL).Info("Downloading pinned components from URL")
	rCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rCtx, http.MethodGet, pinnedURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request for pinned components: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading pinned components from %s: %w", pinnedURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading pinned components from %s: HTTP %d", pinnedURL, resp.StatusCode)
	}
	tmpFile, err := os.CreateTemp("", "pinned_components_*.yml")
	if err != nil {
		return "", fmt.Errorf("creating temp file for pinned components: %w", err)
	}
	defer func() { _ = tmpFile.Close() }()
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return "", fmt.Errorf("writing pinned components to temp file: %w", err)
	}
	logrus.WithField("file", tmpFile.Name()).Info("Pinned components downloaded to temp file")
	return tmpFile.Name(), nil
}

// cloudBuildBefore loads pinned components from a URL or file, sets the enterprise version config flag,
// and generates the version tag from the pinned components release name.
func cloudBuildBefore(ctx context.Context, c *cli.Command) error {
	if !c.Bool(hashreleaseFlag.Name) {
		return nil
	}
	if c.String(imageFlag.Name) == cloudReleaseImage {
		if err := c.Set(imageFlag.Name, cloudDevImage); err != nil {
			return fmt.Errorf("setting operator image to dev: %w", err)
		}
	}
	pinnedFilePath, err := pinnedComponentsFile(ctx, c)
	if err != nil {
		return fmt.Errorf("reading pinned components: %w", err)
	}
	pinned, err := loadPinnedComponents(pinnedFilePath)
	if err != nil {
		return fmt.Errorf("loading pinned components: %w", err)
	}
	if pinned.ReleaseName == "" {
		return fmt.Errorf("hashrelease name missing")
	}
	if err := c.Set(enterpriseVersionsConfigFlag.Name, pinnedFilePath); err != nil {
		return fmt.Errorf("setting enterprise versions from pinned components: %w", err)
	}
	tag, err := generateCloudHashreleaseVersion(pinned.ReleaseName)
	if err != nil {
		return fmt.Errorf("generating cloud image tag: %w", err)
	}
	logrus.WithFields(logrus.Fields{
		"releaseName":       pinned.ReleaseName,
		"enterpriseVersion": pinned.Title,
		"managerVersion":    pinned.Components[managerComponentName].Version,
		"version":           tag,
	}).Info("Generated cloud hashrelease version")
	if err := c.Set(versionFlag.Name, tag); err != nil {
		return fmt.Errorf("setting version: %w", err)
	}
	branch, err := extractReleaseBranch(pinned.Note)
	if err != nil {
		return fmt.Errorf("extracting release branch from pinned components note: %w", err)
	}
	logrus.WithField("branch", branch).Debug("Extracted release branch from pinned components")
	if err := c.Set(enterpriseGitBranchFlag.Name, branch); err != nil {
		return fmt.Errorf("setting enterprise git branch from pinned components: %w", err)
	}
	return nil
}

// extractReleaseBranch looks for the pattern "using <branch> release branch" in the input string
// and extracts the branch name.
func extractReleaseBranch(input string) (string, error) {
	const prefix = "using"
	const suffix = "release branch"

	start := strings.Index(input, prefix)
	if start == -1 {
		return "", fmt.Errorf("expected %q in note %q", prefix, input)
	}

	start += len(prefix)

	end := strings.Index(input[start:], suffix)
	if end == -1 {
		return "", fmt.Errorf("expected %q after %q in note %q", suffix, prefix, input)
	}

	return strings.TrimSpace(input[start : start+end]), nil
}

// cloudSetupHashreleaseBuild modifies the cloud component image config.
func cloudSetupHashreleaseBuild(_ context.Context, c *cli.Command, repoRootDir string) error {
	if registry := c.String(cloudRegistryFlag.Name); registry != "" {
		if err := versions.ModifyComponentImageConfig(repoRootDir, versions.CloudComponentImageConfigRelPath, versions.CloudRegistryConfigKey, addTrailingSlash(registry)); err != nil {
			return fmt.Errorf("updating Cloud registry: %w", err)
		}
	}
	return nil
}

// cloudPublishBefore ensures GitHub release creation for operator-cloud is disabled (as it's not supported) and,
// for hashreleases, sets the version to one generated from pinned components.
func cloudPublishBefore(ctx context.Context, c *cli.Command) error {
	if c.Bool(createGithubReleaseFlag.Name) && !c.Bool(hashreleaseFlag.Name) {
		logrus.Warn("GitHub releases are not supported for operator-cloud, disabling")
		if err := c.Set(createGithubReleaseFlag.Name, "false"); err != nil {
			return fmt.Errorf("setting create github release flag to false: %w", err)
		}
	}
	if !c.Bool(hashreleaseFlag.Name) {
		return nil
	}
	if c.String(imageFlag.Name) == cloudReleaseImage {
		if err := c.Set(imageFlag.Name, cloudDevImage); err != nil {
			return fmt.Errorf("setting operator image to dev: %w", err)
		}
	}
	tag, err := resolveCloudHashreleaseVersion(ctx, c)
	if err != nil {
		return fmt.Errorf("resolving cloud hashrelease version: %w", err)
	}
	logrus.WithField("version", tag).Info("Generated cloud hashrelease version")
	if err := c.Set(versionFlag.Name, tag); err != nil {
		return fmt.Errorf("setting version: %w", err)
	}
	return nil
}

// formatBoolOutput returns the bool as a title-cased string ("True" or "False").
func formatBoolOutput(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// generateCloudHashreleaseVersion constructs a version for cloud image from a release name
// and the current git commit hash shortened to gitHashLength chars, in the format <releaseName>-tesla-<gitHash>.
func generateCloudHashreleaseVersion(releaseName string) (string, error) {
	commit, err := command.Git("rev-parse", fmt.Sprintf("--short=%d", gitHashLength), "HEAD")
	if err != nil {
		return "", fmt.Errorf("getting git commit: %w", err)
	}
	return fmt.Sprintf("%s-tesla-%s", releaseName, commit), nil
}

// resolveCloudHashreleaseVersion determines the version tag for a cloud hashrelease
// by loading the pinned components from a file or URL, extracting the release name, and generating the version tag.
func resolveCloudHashreleaseVersion(ctx context.Context, c *cli.Command) (string, error) {
	filePath, err := pinnedComponentsFile(ctx, c)
	if err != nil {
		return "", err
	}
	pinned, err := loadPinnedComponents(filePath)
	if err != nil {
		return "", err
	}
	if pinned.ReleaseName == "" {
		return "", fmt.Errorf("release name not found in pinned components")
	}
	return generateCloudHashreleaseVersion(pinned.ReleaseName)
}

// cloudPostPublish writes CI output files for the Argo workflow.
func cloudPostPublish(c *cli.Command, isNewRelease bool) error {
	if !c.Bool(hashreleaseFlag.Name) {
		return nil
	}
	if err := os.MkdirAll(outputsDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	if err := os.WriteFile(path.Join(outputsDir, imageTagFileName), []byte(c.String(versionFlag.Name)), 0o644); err != nil {
		return fmt.Errorf("writing image tag file: %w", err)
	}
	if err := os.WriteFile(path.Join(outputsDir, hashreleaseStatusFileName), []byte(formatBoolOutput(isNewRelease)), 0o644); err != nil {
		return fmt.Errorf("writing new hashrelease file: %w", err)
	}
	logrus.WithField("newHashrelease", isNewRelease).Info("Wrote CI output files")
	return nil
}

// PinnedComponents represents the structure of a pinned_components.yml file.
type PinnedComponents struct {
	CalicoVersion `yaml:",inline"`
	Note          string `yaml:"note"`
	ReleaseName   string `yaml:"release_name"`
}

// loadPinnedComponents parses the pinned components from a file path.
func loadPinnedComponents(filePath string) (*PinnedComponents, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading pinned components file: %w", err)
	}
	var pinned PinnedComponents
	if err := yaml.Unmarshal(data, &pinned); err != nil {
		return nil, fmt.Errorf("parsing pinned components: %w", err)
	}
	logrus.WithFields(logrus.Fields{
		"version":     pinned.Title,
		"releaseName": pinned.ReleaseName,
	}).Info("Loaded pinned components")
	return &pinned, nil
}
