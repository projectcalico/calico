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

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/middleware"
	"github.com/tigera/operator/hack/release/internal/versions"
)

// Context keys for branch/prep commands
const (
	branchNameCtxKey              contextKey = "branch-name"
	baseBranchCtxKey              contextKey = "base-branch"
	calicoConfigVersionCtxKey     contextKey = "calico-config-version"
	enterpriseConfigVersionCtxKey contextKey = "enterprise-config-version"
)

var (
	// releaseBranchFormat matches release branches with a version suffix (e.g. release-v1.2).
	releaseBranchFormat = `^(%s-v\d+\.\d+)$`

	// streamFormat validates the stream flag value (e.g. v1.43).
	streamFormat = `^v\d+\.\d+$`

	defaultBaseBranch = "master"

	defaultChangedFiles = []string{
		versions.CalicoConfigPath,
		versions.EnterpriseConfigPath,
		"pkg/components",
		"pkg/imports/crds",
		"pkg/imports/admission",
	}
)

var branchCommand = &cli.Command{
	Name:  "branch",
	Usage: "Release branch operations",
	Commands: []*cli.Command{
		branchCutCommand,
		branchValidateCommand,
	},
}

var branchCutCommand = &cli.Command{
	Name:  "cut",
	Usage: "Create a new branch for the release",
	Description: `The branch command creates a new branch for the release off of the current branch (which should be master or a release branch).
	The new branch name is in the format <release-branch-prefix>-<stream> (e.g. release-v1.43).

	The config versions are updated based on the provided Calico and Enterprise refs, which should point to branches or tags in the respective repositories.
	If the base branch is not a release branch, an empty commit and dev tag are also created on the base branch to allow for proper versioning of future commits on the base branch.`,
	Flags: []cli.Flag{
		streamFlag,
		calicoRefFlag,
		calicoGitRepoFlag,
		enterpriseRefFlag,
		enterpriseGitRepoFlag,
		releaseBranchPrefixFlag,
		devTagSuffixFlag,
		calicoDirFlag,
		enterpriseDirFlag,
		enterpriseRegistryFlag,
		skipBranchCheckFlag,
		skipValidationFlag,
		localFlag,
		gitRemoteFlag,
	},
	Before: middleware.WithLogging(branchCutBefore),
	Action: middleware.WithSummary("branch-cut", func(ctx context.Context, c *cli.Command) (string, map[string]any, error) {
		stream := c.String(streamFlag.Name)
		outputs, err := branchCutAction(ctx, c)
		return stream, outputs, err
	}),
	After: branchCutAfter,
}

// branchCutBeforeCommon handles shared Before logic for both branch and prep
func branchCutBeforeCommon(ctx context.Context, c *cli.Command, scopeContextFn func(context.Context, *cli.Command) (context.Context, error), validateFn func(context.Context, *cli.Command) (context.Context, error)) (context.Context, error) {
	// Start with a clean slate for branch cleanup functions.
	branchCutCleanupFns = nil

	var err error
	ctx, err = scopeContextFn(ctx, c)
	if err != nil {
		return ctx, err
	}

	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validations as requested.", c.Name)
		return ctx, nil
	}

	ctx, err = checkGitClean(ctx)
	if err != nil {
		return ctx, err
	}
	return validateFn(ctx, c)
}

// branchCutContextValuesFunc sets branch cutting context values based on CLI flags
var branchCutContextValuesFunc = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	currentBranch, err := command.GitBranch()
	if err != nil {
		return ctx, fmt.Errorf("getting current branch: %w", err)
	}
	ctx = context.WithValue(ctx, baseBranchCtxKey, currentBranch)
	ctx = context.WithValue(ctx, branchNameCtxKey, fmt.Sprintf("%s-%s", c.String(releaseBranchPrefixFlag.Name), c.String(streamFlag.Name)))
	if calicoRef := c.String(calicoRefFlag.Name); calicoRef != "" {
		ctx = context.WithValue(ctx, calicoConfigVersionCtxKey, calicoRef)
	}
	if enterpriseRef := c.String(enterpriseRefFlag.Name); enterpriseRef != "" {
		ctx = context.WithValue(ctx, enterpriseConfigVersionCtxKey, enterpriseRef)
	}
	return ctx, nil
}

var isValidStream = func(stream string) (bool, error) {
	matched, err := regexp.MatchString(streamFormat, stream)
	if err != nil {
		return false, fmt.Errorf("validating stream format: %w", err)
	}
	return matched, nil
}

var isReleaseBranch = func(releaseBranchPrefix, branch string) (bool, error) {
	matched, err := regexp.MatchString(fmt.Sprintf(releaseBranchFormat, regexp.QuoteMeta(releaseBranchPrefix)), branch)
	if err != nil {
		return false, fmt.Errorf("validating release branch format: %w", err)
	}
	return matched, nil
}

// validateBranchRefs validates that the required ref flags are set for branch creation.
//   - check that the stream flag is in the correct format
//   - check that the operator branch does not already exist
//   - check that both calico and enterprise refs are provided
//   - check that the provided calico and enterprise refs exist as a branch or tag in the remote repository
//   - check that the base operator branch is either a release branch (or master) (if not skipping branch check)
var validateBranchRefs = func(ctx context.Context, c *cli.Command) (context.Context, error) {
	// check that the stream format is valid
	stream := c.String(streamFlag.Name)
	if valid, err := isValidStream(stream); err != nil {
		return ctx, err
	} else if !valid {
		return ctx, fmt.Errorf("stream %q is not valid, expected format: vX.Y (e.g., v1.43)", stream)
	}

	// check that the operator branch does not already exist
	remote := c.String(gitRemoteFlag.Name)
	branchName, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return ctx, err
	}
	out, err := command.GitLsRemoteHeads(remote, branchName)
	if err != nil {
		return ctx, fmt.Errorf("checking if branch %s exists in remote %s: %w", branchName, remote, err)
	}
	if out != "" {
		return ctx, fmt.Errorf("branch %s already exists in remote %s, please choose a different name or delete the existing branch", branchName, remote)
	}

	// check that both calico and enterprise refs are provided
	calicoRef := c.String(calicoRefFlag.Name)
	enterpriseRef := c.String(enterpriseRefFlag.Name)
	if calicoRef == "" || enterpriseRef == "" {
		return ctx, fmt.Errorf("both --%s and --%s are required for branch creation", calicoRefFlag.Name, enterpriseRefFlag.Name)
	}

	// check that the provided calico and enterprise refs exist as a branch or tag in the remote repository
	for _, check := range []struct {
		ref  string
		repo string
		flag string
	}{
		{calicoRef, c.String(calicoGitRepoFlag.Name), calicoRefFlag.Name},
		{enterpriseRef, c.String(enterpriseGitRepoFlag.Name), enterpriseRefFlag.Name},
	} {
		out, err := command.GitLsRemote(fmt.Sprintf("git@github.com:%s", check.repo), check.ref, "--heads", "--tags")
		if err != nil {
			return ctx, fmt.Errorf("checking if ref %q exists in %s: %w", check.ref, check.repo, err)
		}
		if !command.GitRefExistsInRemote(out, check.ref) {
			return ctx, fmt.Errorf("ref %q not found as a branch or tag in %s", check.ref, check.repo)
		}
	}

	// check operator base branch is either the default base branch or a release branch (if not skipping branch check)
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return ctx, err
	}
	if c.Bool(skipBranchCheckFlag.Name) {
		logrus.Warnf("Skipping branch validation as requested.")
		return ctx, nil
	}
	releaseBranch, err := isReleaseBranch(c.String(releaseBranchPrefixFlag.Name), baseBranch)
	if err != nil {
		return ctx, fmt.Errorf("validating current branch: %w", err)
	}
	if baseBranch != defaultBaseBranch && !releaseBranch {
		return ctx, fmt.Errorf("current branch is %s, please switch to %s or a release branch before running this command or use --%s to skip this check", baseBranch, defaultBaseBranch, skipBranchCheckFlag.Name)
	}

	if baseBranch != defaultBaseBranch {
		logrus.WithFields(logrus.Fields{
			"base":     baseBranch,
			"expected": defaultBaseBranch,
		}).Warn("Current branch is not the default base branch")
	}

	return ctx, nil
}

// branchCutPreCommit modifies files in the new branch before committing, and returns a list of changed files to include in the commit.
var branchCutPreCommit = func(ctx context.Context, c *cli.Command, repoRoot string) ([]string, error) {
	// Ensure VERSION_TAG in Makefile matches the calico version in config/
	const makefileRelPath = "Makefile"
	calicoVer, err := versions.CalicoConfigVersions(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("getting calico version from config: %w", err)
	}
	// Use | as sed delimiter to avoid clashing with / in version strings; escape &, |, \ in the replacement.
	title := strings.NewReplacer(`\`, `\\`, `&`, `\&`, `|`, `\|`).Replace(calicoVer.Title)
	if out, err := command.RunInDir(repoRoot, "sed", []string{"-i", fmt.Sprintf(`s|^VERSION_TAG.*|VERSION_TAG := %s|`, title), makefileRelPath}, nil); err != nil {
		logrus.Error(out)
		return nil, fmt.Errorf("updating VERSION_TAG in Makefile: %w", err)
	}
	return []string{makefileRelPath}, nil
}

// Pre-action for branch command.
var branchCutBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	return branchCutBeforeCommon(ctx, c, branchCutContextValuesFunc, validateBranchRefs)
})

// Action for branch command.
var branchCutAction = func(ctx context.Context, c *cli.Command) (map[string]any, error) {
	stream := c.String(streamFlag.Name)
	remote := c.String(gitRemoteFlag.Name)
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return nil, err
	}
	branchName, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return nil, err
	}
	refs := []string{branchName}

	if _, err := branchCutActionCommon(ctx, c, branchCutPreCommit, fmt.Sprintf("build: update config for %s", stream)); err != nil {
		return nil, err
	}
	outputs := map[string]any{
		"release-branch": branchName,
	}
	logrus.WithField("newBranch", branchName).Info("Created new branch")

	// If this was not branched off a release branch, switch back to baseBranch branch to create the dev tag.
	// The dev tag goes on an empty commit on the baseBranch branch so that git describe --tags
	// produces sensible versions for subsequent baseBranch branch commits.
	var nextDevTag, nextStream string
	releaseBranch, err := isReleaseBranch(c.String(releaseBranchPrefixFlag.Name), baseBranch)
	if err != nil {
		return outputs, fmt.Errorf("checking if base branch is a release branch: %w", err)
	} else if !releaseBranch {
		nextStream, nextDevTag, err = nextDevRelease(stream, c.String(devTagSuffixFlag.Name))
		if err != nil {
			return outputs, fmt.Errorf("calculating next dev tag: %w", err)
		}
		logrus.WithField("devTag", nextDevTag).Debugf("Next dev tag to create on %s", baseBranch)
		if out, err := command.Git("switch", baseBranch); err != nil {
			logrus.Error(out)
			return outputs, fmt.Errorf("switching back to %s: %w", baseBranch, err)
		}
		if out, err := command.Git("commit", "--allow-empty", "-m", fmt.Sprintf("Start development on %s", nextStream)); err != nil {
			logrus.Error(out)
			return outputs, fmt.Errorf("creating empty commit on %s: %w", baseBranch, err)
		}
		refs = append(refs, baseBranch)
		if out, err := command.Git("tag", nextDevTag, "-m", fmt.Sprintf("%s development", nextStream)); err != nil {
			logrus.Error(out)
			return outputs, fmt.Errorf("creating git tag %s: %w", nextDevTag, err)
		}
		refs = append(refs, nextDevTag)
		outputs["next-dev-tag"] = nextDevTag
	}

	if c.Bool(localFlag.Name) {
		logrus.WithFields(logrus.Fields{
			"remote":        remote,
			"baseBranch":    baseBranch,
			"newBranch":     branchName,
			"nextDevStream": nextStream,
			"nextDevTag":    nextDevTag,
		}).Warn("Local flag is set, skipping pushing to remote")
		return outputs, nil
	}

	// Push refs to remote - release branch, base branch (with empty commit), and dev tag
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if out, err := command.Git("push", remote, ref); err != nil {
			logrus.Error(out)
			return outputs, fmt.Errorf("pushing %s to remote: %w", ref, err)
		}
		logrus.WithFields(logrus.Fields{
			"ref":    ref,
			"remote": remote,
		}).Infof("Pushed to %s", remote)
	}
	return outputs, nil
}

// nextDevRelease calculates the next stream and dev tag based on the provided stream and devTagSuffix.
// For example, if the stream is v1.43 and the devTagSuffix is 0.dev, it will return v1.44 and v1.44.0-0.dev.
func nextDevRelease(stream, devTagSuffix string) (string, string, error) {
	v, err := semver.Parse(fmt.Sprintf("%s.0", strings.TrimPrefix(stream, "v")))
	if err != nil {
		return "", "", fmt.Errorf("parsing stream version: %w", err)
	}
	if err := v.IncrementMinor(); err != nil {
		return "", "", fmt.Errorf("incrementing minor version: %w", err)
	}
	return fmt.Sprintf("v%d.%d", v.Major, v.Minor), fmt.Sprintf("v%s-%s", v.String(), devTagSuffix), nil
}

var branchCutCleanupFns []func()

var branchCutAfter = cli.AfterFunc(func(_ context.Context, _ *cli.Command) error {
	for i := len(branchCutCleanupFns) - 1; i >= 0; i-- {
		branchCutCleanupFns[i]()
	}
	return nil
})

func switchBranch(ctx context.Context, branchName string) error {
	// get current branch to switch back to later
	baseBranch, err := contextString(ctx, baseBranchCtxKey)
	if err != nil {
		return err
	}
	branchCutCleanupFns = append(branchCutCleanupFns, func() {
		if out, err := command.Git("switch", "-f", baseBranch); err != nil {
			logrus.Error(out)
			logrus.WithError(err).Errorf("Failed to reset to %q branch", baseBranch)
		}
	})
	if out, err := command.Git("switch", "-C", branchName); err != nil {
		logrus.Error(out)
		return fmt.Errorf("creating and switching to branch %s: %w", branchName, err)
	}
	return nil
}

// branchCutActionCommon switches to a new branch, modifies config versions, and commits the changes.
// It reads the branch name and calico/enterprise versions from context (set by Before functions).
// It returns the repo root directory for subsequent operations.
func branchCutActionCommon(ctx context.Context, c *cli.Command, preCommitFunc func(ctx context.Context, c *cli.Command, repoRoot string) (changedFiles []string, err error), commitMsg string) (string, error) {
	branchName, err := contextString(ctx, branchNameCtxKey)
	if err != nil {
		return "", err
	}
	if err := switchBranch(ctx, branchName); err != nil {
		return "", err
	}
	repoRootDir, err := command.GitDir()
	if err != nil {
		return "", fmt.Errorf("getting git directory: %w", err)
	}
	if err := modifyConfigVersions(ctx, c, repoRootDir); err != nil {
		return "", fmt.Errorf("modifying config versions: %w", err)
	}
	var changedFiles []string
	if preCommitFunc != nil {
		changedFiles, err = preCommitFunc(ctx, c, repoRootDir)
		if err != nil {
			return "", fmt.Errorf("running pre-commit function: %w", err)
		}
	}
	if err := commitGitChanges(repoRootDir, commitMsg, changedFiles...); err != nil {
		return "", fmt.Errorf("committing git changes: %w", err)
	}
	return repoRootDir, nil
}

// modifyConfigVersions updates config versions and runs make targets to regenerate files.
// It reads calico/enterprise versions from context (set by Before functions).
func modifyConfigVersions(ctx context.Context, c *cli.Command, repoRootDir string) error {
	// Missing context keys are treated as empty strings; Generate() skips the update for empty versions.
	calicoVersion, _ := ctx.Value(calicoConfigVersionCtxKey).(string)
	enterpriseVersion, _ := ctx.Value(enterpriseConfigVersionCtxKey).(string)
	enterpriseRegistry := c.String(enterpriseRegistryFlag.Name)
	if enterpriseRegistry == "" {
		enterpriseRegistry = quayRegistry
	}
	verCfg := &versions.VersionsConfig{
		RepoRootDir: repoRootDir,
		Calico: versions.VersionConfig{
			Version: calicoVersion,
			Dir:     c.String(calicoDirFlag.Name),
		},
		Enterprise: versions.VersionConfig{
			Version:  enterpriseVersion,
			Registry: addTrailingSlash(enterpriseRegistry),
			Dir:      c.String(enterpriseDirFlag.Name),
		},
	}
	return verCfg.Generate()
}

func commitGitChanges(repoRootDir, msg string, additionalFiles ...string) error {
	changedFiles := append(slices.Clone(defaultChangedFiles), additionalFiles...)
	if out, err := command.GitInDir(repoRootDir, append([]string{"add"}, changedFiles...)...); err != nil {
		logrus.Error(out)
		return fmt.Errorf("staging git changes: %w", err)
	}
	if out, err := command.Git("commit", "-m", msg); err != nil {
		logrus.Error(out)
		return fmt.Errorf("committing git changes: %w", err)
	}
	return nil
}

var branchValidateCommand = &cli.Command{
	Name:  "validate",
	Usage: "Validate a branch cut",
	Flags: []cli.Flag{
		releaseBranchPrefixFlag,
		streamFlag,
		devTagSuffixFlag,
		calicoGitRepoFlag,
		enterpriseGitRepoFlag,
		&cli.StringFlag{
			Name:     "base-branch",
			Category: operatorFlagCategory,
			Usage:    "The base branch the release was cut from (used to decide whether to check the dev tag on master)",
			Sources:  cli.EnvVars("BASE_BRANCH"),
			Value:    "master",
		},
		githubTokenFlag,
	},
	Before: middleware.WithLogging(branchValidateBefore),
	Action: middleware.WithSummary("branch-validate", branchValidateAction),
}

var branchValidateBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	// Verify that gotestsum is installed before running any tests
	if _, err := command.Run("gotestsum", []string{"--version"}, nil); err != nil {
		return ctx, fmt.Errorf("checking gotestsum installation: %w", err)
	}

	// Check release stream is valid format
	stream := c.String(streamFlag.Name)
	if stream == "" {
		return ctx, fmt.Errorf("--stream is required")
	}
	if valid, err := isValidStream(stream); err != nil {
		return ctx, fmt.Errorf("validating stream: %w", err)
	} else if !valid {
		return ctx, fmt.Errorf("stream %q is not valid, expected format: vX.Y", stream)
	}
	return ctx, nil
})

var branchValidateAction = func(ctx context.Context, c *cli.Command) (string, map[string]any, error) {
	repoRoot, err := command.GitDir()
	if err != nil {
		return "", nil, fmt.Errorf("getting git directory: %w", err)
	}
	baseBranch := c.String("base-branch")
	if baseBranch == defaultBaseBranch && c.String(githubTokenFlag.Name) == "" {
		return "", nil, fmt.Errorf("github token is required for validating milestone on %s branch", defaultBaseBranch)
	}
	stream := c.String(streamFlag.Name)
	args := []string{
		"--format=testname",
		"--", "-v", "-count=1",
		"-run", "^TestBranchCut",
		fmt.Sprintf("-stream=%s", stream),
		fmt.Sprintf("-repo=%s", c.String(gitRepoFlag.Name)),
		fmt.Sprintf("-calico-repo=%s", c.String(calicoGitRepoFlag.Name)),
		fmt.Sprintf("-enterprise-repo=%s", c.String(enterpriseGitRepoFlag.Name)),
		fmt.Sprintf("-release-branch-prefix=%s", c.String(releaseBranchPrefixFlag.Name)),
		fmt.Sprintf("-dev-tag-suffix=%s", c.String(devTagSuffixFlag.Name)),
		fmt.Sprintf("-base-branch=%s", baseBranch),
		fmt.Sprintf("-remote=%s", c.String(gitRemoteFlag.Name)),
	}

	// Propagate the GitHub token so gh api calls in the validate suite can authenticate.
	env := os.Environ()
	if token := c.String(githubTokenFlag.Name); token != "" {
		env = append(env, "GH_TOKEN="+token)
	}

	logrus.WithField("args", args).Info("Running branch-validate tests via gotestsum")
	out, err := command.RunInDir(filepath.Join(repoRoot, middleware.ReleaseDir, "validate"), "gotestsum", args, env)
	if err != nil {
		logrus.Error(out)
		return stream, nil, fmt.Errorf("running branch-validate tests: %w", err)
	}
	return stream, nil, nil
}
