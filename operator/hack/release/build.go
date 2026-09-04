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
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/operator/hack/release/internal/command"
	"github.com/projectcalico/calico/operator/hack/release/internal/middleware"
	"github.com/projectcalico/calico/operator/hack/release/internal/setup"
	"github.com/projectcalico/calico/operator/hack/release/internal/versions"
)

// Command to build release artifacts.
var buildCommand = &cli.Command{
	Name:  "build",
	Usage: "Build release artifacts",
	Flags: []cli.Flag{
		versionFlag,
		imageFlag,
		archFlag,
		registryFlag,
		calicoVersionFlag,
		calicoRegistryFlag,
		calicoImagePathFlag,
		hashreleaseFlag,
		skipValidationFlag,
		versionCheckFlag,
		extensionTimeoutFlag,
	},
	Before: middleware.WithLogging(buildBefore),
	Action: middleware.WithSummary("release-build", buildAction),
	After:  buildAfter,
}

// buildCleanupFns collects cleanup functions to run after the build completes (e.g., git reset, temp dir removal).
// Functions are run in reverse order (LIFO) and all errors are collected.
var buildCleanupFns []func(ctx context.Context) error

// Pre-action for release build command.
var buildBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	// Start with a clean slate for build cleanup functions.
	buildCleanupFns = nil

	var err error

	// Run version validations. This is a mandatory check.
	ctx, err = checkVersion(ctx, c)
	if err != nil {
		return ctx, err
	}

	// Skip validations if requested
	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validation as requested.", c.Name)
		return ctx, nil
	}

	// Ensure that git working tree is clean
	ctx, err = checkGitClean(ctx)
	if err != nil {
		return ctx, err
	}

	// No further checks for release builds
	if !c.Bool(hashreleaseFlag.Name) {
		return ctx, nil
	}

	// For hashrelease builds, the Calico version the operator deploys has to be spelled out:
	// the build's own version names the operator image, not the components it installs.
	if c.String(calicoVersionFlag.Name) == "" {
		return ctx, fmt.Errorf("for hashrelease builds, the Calico version must be specified")
	}

	return ctx, nil
})

// Action for release build command.
var buildAction = func(ctx context.Context, c *cli.Command) (string, map[string]any, error) {
	version := c.String(versionFlag.Name)
	repoRootDir, err := command.GitDir()
	if err != nil {
		return version, nil, fmt.Errorf("getting git directory: %w", err)
	}

	buildLog := logrus.WithField("version", version)

	// For hashrelease builds, skip if image is already published.
	if c.Bool(hashreleaseFlag.Name) {
		if published, err := operatorImagePublished(c); err != nil {
			buildLog.WithError(err).Warn("Failed to check if image is already published, proceeding with build")
		} else if published {
			buildLog.Warn("Image is already published, skipping build")
			return version, nil, nil
		}
	}

	// Prepare build environment variables
	buildEnv := append(os.Environ(), fmt.Sprintf("VERSION=%s", version))
	if arches := c.StringSlice(archFlag.Name); len(arches) > 0 {
		buildLog = buildLog.WithField("arches", arches)
		buildEnv = append(buildEnv, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	}
	image := c.String(imageFlag.Name)
	if image != defaultImage {
		buildLog = buildLog.WithField("image", image)
		buildEnv = append(buildEnv, fmt.Sprintf("BUILD_IMAGE=%s", image))
	}
	registry := c.String(registryFlag.Name)
	if registry != "" && registry != defaultRegistry {
		buildLog = buildLog.WithField("registry", registry)
		buildEnv = append(buildEnv,
			fmt.Sprintf("IMAGE_REGISTRY=%s", registry),
			fmt.Sprintf("PUSH_IMAGE_PREFIXES=%s", addTrailingSlash(registry)))
	}
	if c.Bool(hashreleaseFlag.Name) {
		buildLog = buildLog.WithField("hashrelease", true)
		buildEnv = append(buildEnv, fmt.Sprintf("GIT_VERSION=%s", c.String(versionFlag.Name)))
		buildCleanupFns = append(buildCleanupFns, func(ctx context.Context) error {
			if out, err := command.GitInDir(repoRootDir, append([]string{"checkout", "-f"}, defaultChangedFiles...)...); err != nil {
				logrus.Error(out)
				return fmt.Errorf("resetting git state in repo after hashrelease build: %w", err)
			}
			return nil
		})
		hashreleaseEnv, err := setupHashreleaseBuild(c, repoRootDir)
		if err != nil {
			return version, nil, fmt.Errorf("preparing hashrelease build environment: %w", err)
		}
		buildEnv = append(buildEnv, hashreleaseEnv...)
	} else {
		buildLog = buildLog.WithField("release", true)
		// A release publishes every Calico image at the release version, so the operator
		// resolves them there rather than at the branch tag a dev build defaults to.
		buildEnv = append(buildEnv, "RELEASE=true", fmt.Sprintf("CALICO_VERSION=%s", version))
		if setup.IsCloud {
			// Cloud releases carry a -cloud suffix, so VERSION (vX.Y.Z-cloud) differs from the git
			// tag (vX.Y.Z). Pass GIT_VERSION=VERSION so the Makefile's VERSION==GIT_VERSION guard
			// passes and the operator binary reports the -cloud version.
			buildEnv = append(buildEnv, fmt.Sprintf("GIT_VERSION=%s", version))
		}
	}

	// Build the Operator and verify the build
	buildLog.Info("Building Operator")
	if out, err := command.MakeInDir(repoRootDir, "release-build", buildEnv...); err != nil {
		buildLog.Error(out)
		return version, nil, fmt.Errorf("building Operator: %w", err)
	}
	if err := assertOperatorImageVersion(registry, image, version); err != nil {
		return version, nil, fmt.Errorf("asserting operator image version: %w", err)
	}
	listImages(registry, image, version)
	return version, nil, nil
}

// runBuildCleanup runs all registered cleanup functions in reverse order (LIFO),
// logging each failure individually. It returns the joined errors and resets the slice.
func runBuildCleanup(ctx context.Context) error {
	var errs []error
	for i := len(buildCleanupFns) - 1; i >= 0; i-- {
		if err := buildCleanupFns[i](ctx); err != nil {
			logrus.WithError(err).Error("Build cleanup failed")
			errs = append(errs, err)
		}
	}
	buildCleanupFns = nil
	return errors.Join(errs...)
}

// buildAfter runs all registered cleanup functions after the build completes.
// Cleanup errors are logged but intentionally not returned to the CLI framework
// as the build result (success or failure) is what matters.
var buildAfter = cli.AfterFunc(func(ctx context.Context, c *cli.Command) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, c.Duration(extensionTimeoutFlag.Name))
	defer cancel()
	if err := runBuildCleanup(cleanupCtx); err != nil {
		logrus.WithError(err).Error("One or more build cleanup functions failed")
	}
	return nil
})

// List images in the built operator image for debugging purposes.
func listImages(registry, image, version string) {
	fqImage := fmt.Sprintf("%s:%s-%s", path.Join(registry, image), version, runtime.GOARCH)
	out, err := command.Run("docker", []string{"run", "--rm", fqImage, "--print-images", "list"}, nil)
	if err != nil {
		logrus.Error(out)
		logrus.Errorf("listing images: %v", err)
		return
	}
	logrus.Debug(out)
}

// Verify that the built operator image contains the expected version.
func assertOperatorImageVersion(registry, image, expectedVersion string) error {
	fqImage := fmt.Sprintf("%s:%s-%s", path.Join(registry, image), expectedVersion, runtime.GOARCH)
	out, err := command.Run("docker", []string{"run", "--rm", fqImage, "--version"}, nil)
	if err != nil {
		logrus.Error(out)
		return fmt.Errorf("getting operator image version: %w", err)
	}
	logrus.Info(out)
	var imageVersion string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "Operator:") {
			parts := strings.SplitAfterN(line, ":", 2)
			imageVersion = strings.TrimSpace(parts[1])
			break
		}
	}
	if imageVersion != expectedVersion {
		return fmt.Errorf("built operator version %s does not match expected version %s", imageVersion, expectedVersion)
	}
	return nil
}

// setupHashreleaseBuild edits the operator's own image config for hashrelease builds and
// returns the environment that stamps the Calico references into the built operator.
var setupHashreleaseBuild = func(c *cli.Command, repoRootDir string) ([]string, error) {
	image := c.String(imageFlag.Name)
	if image != defaultImage {
		imageParts := strings.SplitN(c.String(imageFlag.Name), "/", 2)
		if err := versions.ModifyComponentImageConfig(repoRootDir, versions.ComponentImageConfigRelPath, versions.OperatorImagePathConfigKey, addTrailingSlash(imageParts[0])); err != nil {
			return nil, fmt.Errorf("updating Operator image path: %w", err)
		}
	}
	registry := c.String(registryFlag.Name)
	if registry != "" && registry != defaultRegistry {
		if err := versions.ModifyComponentImageConfig(repoRootDir, versions.ComponentImageConfigRelPath, versions.OperatorRegistryConfigKey, addTrailingSlash(registry)); err != nil {
			return nil, fmt.Errorf("updating Operator registry: %w", err)
		}
	}

	env := []string{fmt.Sprintf("CALICO_VERSION=%s", c.String(calicoVersionFlag.Name))}
	if registry := c.String(calicoRegistryFlag.Name); registry != "" {
		env = append(env, fmt.Sprintf("CALICO_REGISTRY=%s", addTrailingSlash(registry)))
	}
	if imagePath := c.String(calicoImagePathFlag.Name); imagePath != "" {
		env = append(env, fmt.Sprintf("CALICO_IMAGE_PATH=%s", imagePath))
	}
	return env, nil
}
