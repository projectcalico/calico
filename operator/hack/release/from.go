// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/projectcalico/calico/operator/hack/release/internal/command"
	"github.com/projectcalico/calico/operator/hack/release/internal/middleware"
	"github.com/projectcalico/calico/operator/hack/release/internal/setup"
	"github.com/projectcalico/calico/operator/hack/release/internal/versions"
	"github.com/urfave/cli/v3"
)

// Command to release from a previous version.
var releaseFromCommand = &cli.Command{
	Name:  "from",
	Usage: "Release a new operator image version using a previous version as the base",
	Flags: []cli.Flag{
		baseOperatorFlag,
		versionFlag,
		exceptCalicoFlag,
		exceptEnterpriseFlag,
		publishFlag,
		archFlag,
		registryFlag,
		imageFlag,
		devTagSuffixFlag,
		skipValidationFlag,
	},
	Before: middleware.WithLogging(releaseFromBefore),
	Action: releaseFromAction,
}

// Pre-action for "release from" command.
var releaseFromBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validation as requested.", c.Name)
		return ctx, nil
	}

	ctx, err := checkGitClean(ctx)
	if err != nil {
		return ctx, err
	}
	version := c.String(versionFlag.Name)
	if c.String(baseOperatorFlag.Name) == version {
		return ctx, fmt.Errorf("base version and new version cannot be the same")
	}
	if isRelease, err := setup.IsValidReleaseVersion(version); err != nil {
		return ctx, fmt.Errorf("determining if version is a release: %s", err)
	} else if isRelease && c.Bool(publishFlag.Name) {
		logrus.Warn("You are about to publish a release version. Ensure this is intended.")
		return ctx, nil
	}
	hashreleaseRegex, err := regexp.Compile(fmt.Sprintf(hashreleaseFormat, c.String(devTagSuffixFlag.Name)))
	if err != nil {
		return ctx, fmt.Errorf("compiling hashrelease regex: %s", err)
	}
	if !hashreleaseRegex.MatchString(version) {
		if c.Bool(publishFlag.Name) && c.String(registryFlag.Name) == defaultRegistry && c.String(imageFlag.Name) == defaultImage {
			return ctx, fmt.Errorf("cannot use the default registry and image for publishing operator version %q. "+
				"Either update registry and/or image flag OR specify version in the format ", version)
		}
	}
	return ctx, nil
})

// Action executed for "release from" command.
var releaseFromAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	// get root directory of operator git repo
	repoRootDir, err := command.GitDir()
	if err != nil {
		return fmt.Errorf("getting git root directory: %s", err)
	}

	// fetch config from the base version of the operator
	baseVersion := c.String(baseOperatorFlag.Name)
	gitRef, err := extractGitRef(baseVersion)
	if err != nil {
		return fmt.Errorf("extracting git ref from %q: %s", baseVersion, err)
	}
	if err := versions.ReplaceConfigVersions(repoRootDir, gitRef); err != nil {
		return fmt.Errorf("replacing config versions with content from git ref %q: %s", gitRef, err)
	}

	// Apply new version overrides
	if calicoOverrides := c.StringSlice(exceptCalicoFlag.Name); len(calicoOverrides) > 0 {
		cmpts := make(map[string]string)
		for _, override := range calicoOverrides {
			parts := strings.Split(override, ":")
			cmpts[parts[0]] = parts[1]
		}
		logrus.WithField("components", cmpts).Debug("Applying Calico version overrides")
		if err := versions.UpdateCalicoComponents(repoRootDir, cmpts); err != nil {
			return fmt.Errorf("overriding calico config: %s", err)
		}
	}
	if enterpriseOverrides := c.StringSlice(exceptEnterpriseFlag.Name); len(enterpriseOverrides) > 0 {
		cmpts := make(map[string]string)
		for _, override := range enterpriseOverrides {
			parts := strings.Split(override, ":")
			cmpts[parts[0]] = parts[1]
		}
		logrus.WithField("components", cmpts).Debug("Applying Enterprise version overrides")
		if err := versions.UpdateEnterpriseComponents(repoRootDir, cmpts); err != nil {
			return fmt.Errorf("overriding enterprise config: %s", err)
		}
	}

	// Build either a new release or a new hashrelease operator
	version := c.String(versionFlag.Name)
	isReleaseVersion, err := setup.IsValidReleaseVersion(version)
	if err != nil {
		return fmt.Errorf("determining if version is a release: %s", err)
	} else if isReleaseVersion {
		return newOperator(repoRootDir, version, c.String(gitRemoteFlag.Name), c.Bool(publishFlag.Name))
	}

	return newHashreleaseOperator(repoRootDir, version, c.String(imageFlag.Name), c.String(registryFlag.Name), c.StringSlice(archFlag.Name), c.Bool(publishFlag.Name))
})

// newOperator handles creating a new operator release.
// If publish is true, it will push a new tag to the git remote to trigger a release.
// Otherwise, it will only commit the changes to the git repo locally.
func newOperator(dir, version, remote string, publish bool) error {
	if out, err := command.GitInDir(dir, "add", "config/"); err != nil {
		logrus.Error(out)
		return fmt.Errorf("adding changes in git: %s", err)
	}
	if out, err := command.Git("commit", "-m", fmt.Sprintf("Release %s", version)); err != nil {
		logrus.Error(out)
		return fmt.Errorf("committing changes in git: %s", err)
	}
	if _out, err := command.Git("tag", version); err != nil {
		logrus.Error(_out)
		return fmt.Errorf("tagging release in git: %s", err)
	}
	if !publish {
		logrus.Info("skip pushing tag to git for publishing release")
		return nil
	}
	if out, err := command.Git("push", remote, version); err != nil {
		logrus.Error(out)
		return fmt.Errorf("pushing tag in git: %s", err)
	}
	logrus.Warn("Ensure that the changes are merged into the main branch as well.")
	logrus.Info("Follow the release progress in CI.")
	return nil
}

// newHashreleaseOperator creates a new operator for a hashrelease.
// if publish is true, it will also publish the operator to registry.
func newHashreleaseOperator(dir, version, imageName, registry string, arches []string, publish bool) error {
	defer func() {
		if out, err := command.GitInDir(dir, "checkout", "config/"); err != nil {
			logrus.Error(out)
			logrus.WithError(err).Error("reverting changes in config/")
		}
	}()
	if err := buildHashreleaseOperator(dir, version, imageName, registry, arches); err != nil {
		return fmt.Errorf("building operator: %s", err)
	}
	if !publish {
		logrus.Info("skip publishing images to registry")
		return nil
	}
	return publishHashreleaseOperator(version, imageName, registry, arches)
}

func buildHashreleaseOperator(dir, version, imageName, registry string, arches []string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	env = append(env, fmt.Sprintf("GIT_VERSION=%s", version))
	env = append(env, fmt.Sprintf("BUILD_IMAGE=%s", imageName))
	if out, err := command.MakeInDir(dir, "image-all", env...); err != nil {
		logrus.Error(out)
		return fmt.Errorf("building operator images: %w", err)
	}
	for _, arch := range arches {
		tag := fmt.Sprintf("%s/%s:%s-%s", registry, imageName, version, arch)
		if out, err := command.Run("docker", []string{
			"tag",
			fmt.Sprintf("%s:latest-%s", imageName, arch),
			tag,
		}, env); err != nil {
			logrus.Error(out)
			return fmt.Errorf("tagging operator %s image: %w", arch, err)
		}
		logrus.WithField("tag", tag).Debug("Built image")
	}
	return nil
}

// publishHashreleaseOperator publishes the hashrelease operator to registry.
func publishHashreleaseOperator(version, imageName, registry string, archs []string) error {
	multiArchTags := []string{}
	for _, arch := range archs {
		tag := fmt.Sprintf("%s/%s:%s-%s", registry, imageName, version, arch)
		if out, err := command.Run("docker", []string{"push", tag}, nil); err != nil {
			logrus.Error(out)
			return fmt.Errorf("pushing %s image %s: %w", arch, tag, err)
		}
		logrus.WithField("tag", tag).Debug("Pushed image")
		multiArchTags = append(multiArchTags, tag)
	}
	image := fmt.Sprintf("%s/%s:%s", registry, imageName, version)
	cmd := []string{"manifest", "create", image}
	for _, tag := range multiArchTags {
		cmd = append(cmd, "--amend", tag)
	}
	if out, err := command.Run("docker", cmd, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("creating manifest for image %s: %w", image, err)
	}
	if out, err := command.Run("docker", []string{"manifest", "push", "--purge", image}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("pushing manifest: %w", err)
	}
	logrus.WithField("image", image).Debug("Pushed manifest")
	return nil
}

// extractGitRef returns the tag for a release version
// or the git hash for a hashrelease version from the baseVersion.
func extractGitRef(baseVersion string) (string, error) {
	isReleaseVersion, err := setup.IsValidReleaseVersion(baseVersion)
	if err != nil {
		return "", fmt.Errorf("determining if version is a release: %s", err)
	}
	if isReleaseVersion {
		return baseVersion, nil
	}
	gitHashRegex, err := regexp.Compile(`g([0-9a-f]{12})`)
	if err != nil {
		return "", fmt.Errorf("compiling git hash regex: %s", err)
	}
	matches := gitHashRegex.FindStringSubmatch(baseVersion)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("finding git hash in base version")
}
