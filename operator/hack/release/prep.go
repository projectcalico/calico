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
	"github.com/projectcalico/calico/operator/hack/release/internal/command"
	"github.com/projectcalico/calico/operator/hack/release/internal/middleware"
	"github.com/projectcalico/calico/operator/hack/release/internal/setup"
	"github.com/projectcalico/calico/operator/hack/release/internal/versions"
	"github.com/urfave/cli/v3"
)

// Command to prepare repo for a new release.
var prepCommand = &cli.Command{
	Name:  "prep",
	Usage: "Prepare for a new release",
	Description: `This involves updating version configuration files, creating a new git branch with the changes,
pushing the branch to remote, and creating a PR against the release branch.

The Calico and Enterprise versions specified must exist as a tag in their respective GitHub repositories.
Otherwise, use the environment variables "CALICO_CRDS_DIR" and "ENTERPRISE_CRDS_DIR"
to point to local repositories for Calico and Enterprise respectively.`,
	Flags: []cli.Flag{
		versionFlag,
		releaseBranchPrefixFlag,
		calicoVersionFlag,
		calicoDirFlag,
		calicoGitRepoFlag,
		enterpriseVersionFlag,
		enterpriseDirFlag,
		enterpriseGitRepoFlag,
		enterpriseRegistryFlag,
		skipValidationFlag,
		skipMilestoneFlag,
		skipBranchCheckFlag,
		skipRepoCheckFlag,
		githubTokenFlag,
		localFlag,
	},
	Before: middleware.WithLogging(prepBefore),
	Action: prepAction,
	After:  branchCutAfter,
}

// validatePrepRefs checks the required refs for release prep:
//   - check that at least one of calico or enterprise version is provided
//   - if calico version is not provided, check that the version in calico_versions.yml is a released version
//   - check that the provided calico and enterprise refs exist as a tag in the remote repository (if local directory not provided)
//   - check that the base branch is a release branch (if not skipped)
var validatePrepRefs = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	// check that at least one of calico/enterprise version is set for prep
	ctx, err := checkAtLeastOneOfFlags(ctx, c, calicoVersionFlag.Name, enterpriseVersionFlag.Name)
	if err != nil {
		return ctx, err
	}

	// If Calico is not passed in, check the version in calico_versions.yml is a released version.
	// An operator release must always include a released Calico version.
	calicoVersion := c.String(calicoVersionFlag.Name)
	if calicoVersion != "" {
		return ctx, nil
	}
	dir, err := command.GitDir()
	if err != nil {
		return ctx, fmt.Errorf("error getting git directory: %w", err)
	}
	versions, err := versions.CalicoConfigVersions(dir)
	if err != nil {
		return ctx, fmt.Errorf("error retrieving Calico version: %w", err)
	}
	calicoVersion = versions.Title
	if valid, err := setup.IsValidCalicoReleaseVersion(calicoVersion); err != nil {
		return ctx, fmt.Errorf("error validating Calico version format: %w", err)
	} else if !valid {
		return ctx, fmt.Errorf("every release must contain a released Calico version, but found %s", calicoVersion)
	}

	// check that the ref for calico and/or enterprise provided exists as a tag in the specified remote repository
	// unless a local directory is provided for the respective component, in which case we assume the version exists since it is being pulled from the local repo
	for _, check := range []struct {
		repo     string
		tag      string
		flag     string
		localDir string
	}{
		{tag: calicoVersion, repo: c.String(calicoGitRepoFlag.Name), localDir: c.String(calicoDirFlag.Name), flag: calicoVersionFlag.Name},
		{tag: c.String(enterpriseVersionFlag.Name), repo: c.String(enterpriseGitRepoFlag.Name), localDir: c.String(enterpriseDirFlag.Name), flag: enterpriseVersionFlag.Name},
	} {
		if check.tag == "" {
			continue
		}
		if check.localDir != "" {
			logrus.Warnf("Local directory provided for %s, skipping remote ref validation", check.flag)
			continue
		}
		out, err := command.GitLsRemoteTags(fmt.Sprintf("git@github.com:%s", check.repo), check.tag)
		if err != nil {
			return ctx, fmt.Errorf("checking if ref %q exists in %s: %w", check.tag, check.repo, err)
		}
		if !command.GitRefExistsInRemote(out, check.tag) {
			return ctx, fmt.Errorf("ref %q not found as a tag in %s", check.tag, check.repo)
		}
	}

	// check operator base branch is a release branch unless skipped
	if c.Bool(skipBranchCheckFlag.Name) {
		logrus.Warnf("Skipping branch validation as requested.")
		return ctx, nil
	}
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return ctx, err
	}
	releaseBranch, err := isReleaseBranch(c.String(releaseBranchPrefixFlag.Name), baseBranch)
	if err != nil {
		return ctx, fmt.Errorf("validating current branch: %w", err)
	}
	if !releaseBranch {
		return ctx, fmt.Errorf("current branch %s is not a release branch", baseBranch)
	}
	return ctx, nil
}

// prepContextValuesFunc sets context values for the prep command based on CLI flags.
var prepContextValuesFunc = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	baseBranch, err := command.Git("branch", "--show-current")
	if err != nil {
		return ctx, fmt.Errorf("getting current branch: %w", err)
	}
	ctx = context.WithValue(ctx, baseBranchCtxKey, baseBranch)

	// Extract repo information from CLI repo flag into context
	ctx, err = addRepoInfoToCtx(ctx, c.String(gitRepoFlag.Name))
	if err != nil {
		return ctx, err
	}

	// Set branch cutting context values based on CLI flags
	version := c.String(versionFlag.Name)
	ctx = context.WithValue(ctx, versionCtxKey, version)
	ctx = context.WithValue(ctx, branchNameCtxKey, fmt.Sprintf("build-%s", version))
	if calicoVer := c.String(calicoVersionFlag.Name); calicoVer != "" {
		ctx = context.WithValue(ctx, calicoConfigVersionCtxKey, calicoVer)
	}
	if epVer := c.String(enterpriseVersionFlag.Name); epVer != "" {
		ctx = context.WithValue(ctx, enterpriseConfigVersionCtxKey, epVer)
	}
	return ctx, nil
}

// Pre-action for release prep command.
var prepBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	var err error

	ctx, err = branchCutBeforeCommon(ctx, c, prepContextValuesFunc, validatePrepRefs)
	if err != nil {
		return ctx, err
	}

	if token := c.String(githubTokenFlag.Name); token == "" && !c.Bool(localFlag.Name) {
		return ctx, fmt.Errorf("GitHub token must be provided via --%s flag or GITHUB_TOKEN environment variable", githubTokenFlag.Name)
	}

	return ctx, nil
})

// Action executed for release prep command.
var prepAction = middleware.WithSummary("release-prep", func(ctx context.Context, c *cli.Command) (string, map[string]any, error) {
	version := c.String(versionFlag.Name)
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return version, nil, err
	}
	prepBranch, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return version, nil, err
	}
	repoRootDir, err := branchCutActionCommon(ctx, c, nil, fmt.Sprintf("build: %s release", version))
	if err != nil {
		return version, nil, err
	}
	outputs := map[string]any{"branch": prepBranch}

	// If local flag is set, skip pushing prep branch and creating PR
	if c.Bool(localFlag.Name) {
		logrus.WithField("branch", prepBranch).Warn("Local flag set, no remote changes will be made")
		logrus.Infof("Branch for releasing %s (%s) is ready to be pushed and a PR created", version, prepBranch)
		return version, outputs, nil
	}

	// Push branch to remote
	gitRemote := c.String(gitRemoteFlag.Name)
	logrus.Debugf("Pushing branch %s to %s", prepBranch, gitRemote)
	if out, err := command.Git("push", "--force", "--set-upstream", gitRemote, prepBranch); err != nil {
		logrus.Error(out)
		return version, outputs, fmt.Errorf("error pushing branch %s to remote %s: %w", prepBranch, gitRemote, err)
	}

	// Attempt to create PR for the release prep branch
	remoteURL, err := command.Git("config", "--get", fmt.Sprintf("remote.%s.url", gitRemote))
	if err != nil {
		return version, outputs, fmt.Errorf("error getting remote URL for %s: %w", gitRemote, err)
	}
	githubUser := strings.Split(remoteURL[strings.Index(remoteURL, "git@github.com:")+len("git@github.com:"):strings.LastIndex(remoteURL, ".git")], "/")[0]

	githubOrg, err := contextString(ctx, githubOrgCtxKey)
	if err != nil {
		return version, outputs, err
	}
	githubRepo, err := contextString(ctx, githubRepoCtxKey)
	if err != nil {
		return version, outputs, err
	}
	headBranch := prepBranch
	if githubUser != githubOrg {
		// Forked repo, need to specify head as user:branch
		headBranch = fmt.Sprintf("%s:%s", githubUser, headBranch)
	}
	ctx = context.WithValue(ctx, headBranchCtxKey, prepBranch)
	args := []string{
		"pr", "create", "--fill",
		"--repo", fmt.Sprintf("%s/%s", githubOrg, githubRepo),
		"--base", baseBranch,
		"--head", headBranch,
	}
	if c.String(gitRemoteFlag.Name) == mainRepo {
		// If this is not targeting a fork, add additional details to the PR
		args = append(args, []string{
			// include release team as reviewers
			"--reviewer", "tigera/release-team",
			// set milestone to the version being released
			"--milestone", version,
			// add labels for automation
			"--label", "release-note-not-required,docs-not-required,merge-when-ready,squash-commits,delete-branch",
		}...)
	}
	logrus.WithField("args", strings.Join(args, " ")).Debug("Creating PR for release preparation")
	if pr, err := command.RunInDir(repoRootDir, "hack/bin/gh", args, nil); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return version, outputs, fmt.Errorf("failed to create PR: %w", err)
		}
		logrus.Warnf("PR already exists. Find PR at: https://github.com/%s/%s/pulls?q=is%%3Aopen+head%%3A%s", githubOrg, githubRepo, prepBranch)
	} else {
		logrus.WithField("PR", pr).Info("Created PR")
	}

	// Skip milestone management if requested or if using a forked repo
	if c.Bool(skipMilestoneFlag.Name) {
		return version, outputs, nil
	} else if c.String(gitRepoFlag.Name) != mainRepo && !c.Bool(skipRepoCheckFlag.Name) {
		return version, outputs, fmt.Errorf("cannot manage milestones when forked repo (%s); either use the main repo (%s) or set flag to skip repo check", c.String(gitRepoFlag.Name), mainRepo)
	}
	if err := manageStreamMilestone(ctx, c.String(githubTokenFlag.Name)); err != nil {
		return version, outputs, err
	}
	return version, outputs, nil
})
