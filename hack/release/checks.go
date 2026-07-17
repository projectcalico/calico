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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/setup"
	"github.com/urfave/cli/v3"
)

// check that the git working tree is clean.
var checkGitClean = func(ctx context.Context) (context.Context, error) {
	out, err := command.Git("status", "--porcelain")
	if err != nil {
		return ctx, fmt.Errorf("checking git working tree status: %w", err)
	}
	if strings.TrimSpace(out) != "" {
		return ctx, fmt.Errorf("git working tree is dirty, please commit or stash changes before proceeding")
	}
	return ctx, nil
}

// check that the provided version matches the git version.
// This is required for releases, but skipped for hashreleases.
var checkVersionMatchesGitVersion = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	version := c.String(versionFlag.Name)
	checkLog := logrus.WithField("version", version)
	if c.Bool(hashreleaseFlag.Name) {
		checkLog.Debug("Skipping version check for hashrelease")
		return ctx, nil
	}
	// Not using command.GitVersion() so that on a clean tagged HEAD it returns bare "vX.Y.Z"
	// for accurate comparison against the user-provided version.
	// command.GitVersion() uses --long for build-identifier purposes and would always append "-0-g<sha>".
	gitVer, err := command.Git("describe", "--tags", "--abbrev=12", "--dirty")
	if err != nil {
		return ctx, fmt.Errorf("getting git version: %w", err)
	}
	checkLog.WithField("git-version", gitVer).Debug("Checking version matches git version")
	checkLog.Info("Using versions")
	if version != gitVer {
		return ctx, fmt.Errorf("provided version %q does not match git version %q. This is required for releases. \n"+
			"If building a hashrelease, use either the --%s flag or set environment variable %s=true", version, gitVer, hashreleaseFlag.Name, hashreleaseFlagEnvVar)
	}
	return ctx, nil
}

var checkVersionFormat = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	version := c.String(versionFlag.Name)
	checkLog := logrus.WithField("version", version)
	if c.Bool(hashreleaseFlag.Name) {
		checkLog.Debug("Skipping version check for hashrelease")
		return ctx, nil
	}
	checkLog.Debug("Checking version format")
	if isRelease, err := setup.IsValidReleaseVersion(version); err != nil {
		return ctx, fmt.Errorf("checking version format: %w", err)
	} else if !isRelease {
		return ctx, fmt.Errorf("provided version %q is not a valid release version. \n"+
			"If building a hashrelease, use either the --%s flag or set environment variable %s=true", version, hashreleaseFlag.Name, hashreleaseFlagEnvVar)
	}
	return ctx, nil
}

var checkVersion = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	if !c.Bool(versionCheckFlag.Name) {
		logrus.Warn("Skipping version check, this is not recommended for releases")
		return ctx, nil
	}
	ctx, err := checkVersionFormat(ctx, c)
	if err != nil {
		return ctx, err
	}
	return checkVersionMatchesGitVersion(ctx, c)
}

// check that at least one of the given flags is set to a non-empty value.
var checkAtLeastOneOfFlags = func(ctx context.Context, c *cli.Command, flagNames ...string) (context.Context, error) {
	for _, flag := range flagNames {
		if c.String(flag) != "" {
			return ctx, nil
		}
	}
	formatted := make([]string, len(flagNames))
	for i, name := range flagNames {
		formatted[i] = "--" + name
	}
	return ctx, fmt.Errorf("at least one of the following flags must be set: %s", strings.Join(formatted, ", "))
}
