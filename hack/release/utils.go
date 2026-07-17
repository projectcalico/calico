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
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tigera/operator/hack/release/internal/setup"
	"github.com/tigera/operator/hack/release/internal/versions"
)

// defaultRegistry and defaultImage are the publish defaults for the active build variant. They are
// resolved by the setup package at its init() (before this package's vars initialize), so both
// these vars and the flag defaults that capture them (see flags.go) get the correct enterprise or
// cloud values with no later fix-up.
var (
	defaultRegistry = setup.DefaultRegistry
	defaultImage    = setup.DefaultImage
)

const (
	dockerHub    = "docker.io"
	quayRegistry = "quay.io"

	mainRepo = "tigera/operator"

	releaseFormat           = `^v\d+\.\d+\.\d+$`
	enterpriseReleaseFormat = `^v\d+\.\d+\.\d+(-\d+\.\d+)?$`
	hashreleaseFormat       = `^v\d+\.\d+\.\d+-%s-\d+-g[a-f0-9]{12}-[a-z0-9-]+$`
	baseVersionFormat       = `^v\d+\.\d+\.\d+(-%s-\d+-g[a-f0-9]{12}-[a-z0-9-]+)?$`
)

// Context keys
const (
	githubOrgCtxKey  contextKey = "github-org"
	githubRepoCtxKey contextKey = "github-repo"
	versionCtxKey    contextKey = "version"
	headBranchCtxKey contextKey = "head-branch"
)

type contextKey string

// contextString extracts a string value from context, returning an error if the key is not set.
func contextString(ctx context.Context, key contextKey) (string, error) {
	v, ok := ctx.Value(key).(string)
	if !ok {
		return "", fmt.Errorf("required context value %q not set", string(key))
	}
	return v, nil
}

type (
	CalicoVersion = versions.CalicoVersion
)

func addRepoInfoToCtx(ctx context.Context, repo string) (context.Context, error) {
	if ctx.Value(githubOrgCtxKey) != nil && ctx.Value(githubRepoCtxKey) != nil {
		return ctx, nil
	}
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return ctx, fmt.Errorf("invalid repo format, expected 'org/repo', got: %s", repo)
	}
	ctx = context.WithValue(ctx, githubOrgCtxKey, parts[0])
	ctx = context.WithValue(ctx, githubRepoCtxKey, parts[1])
	return ctx, nil
}

// isReleaseVersionFormat checks if the version in the format vX.Y.Z.
func isReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(releaseFormat)
	if err != nil {
		return false, fmt.Errorf("compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

// isEnterpriseReleaseVersionFormat checks if the version is in the format vX.Y.Z or vX.Y.Z-A.B.
func isEnterpriseReleaseVersionFormat(version string) (bool, error) {
	releaseRegex, err := regexp.Compile(enterpriseReleaseFormat)
	if err != nil {
		return false, fmt.Errorf("compiling release regex: %s", err)
	}
	return releaseRegex.MatchString(version), nil
}

func isPrereleaseVersion(rootDir string) (bool, error) {
	enterpriseVer, err := versions.EnterpriseConfigVersions(rootDir)
	if err != nil {
		return false, fmt.Errorf("retrieving Enterprise version: %s", err)
	}
	return isPrereleaseEnterpriseVersion(enterpriseVer.Title)
}

// Check if the Enterprise version is a prerelease version.
// First, it has to be in the release format, otherwise it returns false.
// Then it converts to semver and returns true if there is a prerelease component.
func isPrereleaseEnterpriseVersion(enterpriseVer string) (bool, error) {
	release, err := isEnterpriseReleaseVersionFormat(enterpriseVer)
	if err != nil {
		return false, fmt.Errorf("checking Enterprise version format: %s", err)
	}
	if !release {
		return false, nil
	}
	ver, err := semver.NewVersion(enterpriseVer)
	if err != nil {
		return false, fmt.Errorf("parsing Enterprise version (%s): %s", enterpriseVer, err)
	}
	return ver.Prerelease() != "", nil
}

// Ensure string ends with a slash, if empty string returns empty string.
func addTrailingSlash(registry string) string {
	if registry == "" {
		return ""
	}
	if strings.HasSuffix(registry, "/") {
		return registry
	}
	return registry + "/"
}
