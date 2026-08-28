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

package validate

import (
	"flag"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/blang/semver/v4"

	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/versions"
)

const defaultBaseBranch = "master"

var (
	remote              = flag.String("remote", "origin", "Git remote for operator repo")
	baseBranch          = flag.String("base-branch", defaultBaseBranch, "The base branch the release was cut from")
	stream              = flag.String("stream", "", "Operator release stream, e.g. v1.43")
	releaseBranchPrefix = flag.String("release-branch-prefix", "release", "Release branch prefix")
	devTagSuffix        = flag.String("dev-tag-suffix", "0.dev", "Dev tag suffix")
	repo                = flag.String("repo", "tigera/operator", "Operator GitHub repo")
	calicoRepo          = flag.String("calico-repo", "projectcalico/calico", "Calico GitHub repo")
	enterpriseRepo      = flag.String("enterprise-repo", "tigera/calico-private", "Calico Enterprise GitHub repo")
)

func requireStream(t *testing.T) string {
	t.Helper()
	if *stream == "" {
		t.Fatal("no stream provided for branch-cut validation test")
	}
	return *stream
}

// releaseBranchName returns the expected release branch name for the stream.
func releaseBranchName(stream string) string {
	return fmt.Sprintf("%s-%s", *releaseBranchPrefix, stream)
}

func checkGitBranchExists(t *testing.T, remote, branch string) {
	t.Helper()
	out, err := command.GitLsRemoteHeads(remote, branch)
	if err != nil {
		t.Fatalf("git ls-remote --heads %s %s failed: %v", remote, branch, err)
	}
	if !command.GitRefExistsInRemote(out, branch) {
		t.Fatalf("branch %q does not exist in remote %q", branch, remote)
	}
	t.Logf("branch %s exists in remote %s", branch, remote)
}

func calicoConfigVersions(t *testing.T, ref string) *versions.CalicoVersion {
	t.Helper()
	v, err := versions.GitRefConfigCalicoVersion(ref)
	if err != nil {
		t.Fatalf("failed to get Calico config versions: %v", err)
	}
	if v.Title == "" {
		t.Fatalf("no version title found in %s", versions.CalicoConfigPath)
	}
	return v
}

func enterpriseConfigVersions(t *testing.T, ref string) *versions.CalicoVersion {
	t.Helper()
	v, err := versions.GitRefConfigEnterpriseVersion(ref)
	if err != nil {
		t.Fatalf("failed to get Enterprise config versions: %v", err)
	}
	if v.Title == "" {
		t.Fatalf("no version title found in %s", versions.EnterpriseConfigPath)
	}
	return v
}

// fetchReleaseBranch fetches the release branch ref so git show works.
func fetchReleaseBranch(t *testing.T, branch string) string {
	t.Helper()
	if _, err := command.Git("fetch", *remote, branch); err != nil {
		t.Fatalf("failed to fetch %s: %v", branch, err)
	}
	return fmt.Sprintf("%s/%s", *remote, branch)
}

// --- Test functions ---

func TestBranchCutReleaseBranchInRemote(t *testing.T) {
	stream := requireStream(t)
	branch := releaseBranchName(stream)

	checkGitBranchExists(t, *remote, branch)
}

func TestBranchCutCalico(t *testing.T) {
	stream := requireStream(t)
	branch := releaseBranchName(stream)
	ref := fetchReleaseBranch(t, branch)

	cv := calicoConfigVersions(t, ref)
	if cv.Title == defaultBaseBranch {
		t.Fatalf("calico version is still %s on release branch", defaultBaseBranch)
	}

	checkGitBranchExists(t, fmt.Sprintf("git@github.com:%s.git", *calicoRepo), cv.Title)

	// Check that the version in the config file matches the VERSION_TAG in Makefile.
	content, err := command.GitShowFile(fmt.Sprintf("%s/%s", *remote, branch), "Makefile")
	if err != nil {
		t.Fatalf("git show Makefile failed: %v", err)
	}
	versionTag, err := extractMakefileVar(content, "VERSION_TAG")
	if err != nil {
		t.Fatalf("extracting VERSION_TAG from Makefile: %v", err)
	}
	if versionTag != cv.Title {
		t.Fatalf("calico version in config file (%s) does not match VERSION_TAG in Makefile (%s)", cv.Title, versionTag)
	}
}

// extractMakefileVar returns the value assigned to name on the first matching
// top-level assignment in content. Recognizes `=`, `:=`, `::=`, and `?=`.
func extractMakefileVar(content, name string) (string, error) {
	pattern := fmt.Sprintf(`(?m)^%s\s*(?:::?|\?)?=\s*(.*?)\s*$`, regexp.QuoteMeta(name))
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("compiling regex for %s: %w", name, err)
	}
	m := re.FindStringSubmatch(content)
	if m == nil {
		return "", fmt.Errorf("%s assignment not found", name)
	}
	return m[1], nil
}

func TestBranchCutEnterprise(t *testing.T) {
	stream := requireStream(t)
	branch := releaseBranchName(stream)
	ref := fetchReleaseBranch(t, branch)

	cv := enterpriseConfigVersions(t, ref)
	if cv.Title == defaultBaseBranch {
		t.Fatalf("enterprise version is still %s on release branch", defaultBaseBranch)
	}

	checkGitBranchExists(t, fmt.Sprintf("git@github.com:%s.git", *enterpriseRepo), cv.Title)
}

func TestBranchCutNextDevRelease(t *testing.T) {
	stream := requireStream(t)

	if *baseBranch != defaultBaseBranch {
		t.Skipf("skipping dev tag check: base branch is %q (not %s)", *baseBranch, defaultBaseBranch)
	}

	// Determine next version tag for the stream by incrementing the minor version of the stream
	// and appending the dev tag suffix, e.g. v1.43 -> v1.44.0-dev
	version, err := semver.Parse(fmt.Sprintf("%s.0", strings.TrimPrefix(stream, "v")))
	if err != nil {
		t.Fatalf("failed to parse stream %q as semver: %v", stream, err)
	}
	if err := version.IncrementMinor(); err != nil {
		t.Fatalf("failed to increment minor version: %v", err)
	}

	t.Run("next dev tag", func(t *testing.T) {
		expectedTag := fmt.Sprintf("v%s-%s", version.String(), *devTagSuffix)

		out, err := command.GitLsRemoteTags(*remote, expectedTag)
		if err != nil {
			t.Fatalf("getting tag ref (%s) in remote %q: %v", expectedTag, *remote, err)
		}
		if !command.GitRefExistsInRemote(out, expectedTag) {
			t.Fatalf("dev tag %q does not exist on remote %q", expectedTag, *remote)
		}
		t.Logf("found dev tag %q on remote %q", expectedTag, *remote)
	})

	t.Run("next dev milestone", func(t *testing.T) {
		expectedMilestone := fmt.Sprintf("v%s", version.String())
		exists, err := command.GitHubMilestoneOpen(*repo, expectedMilestone)
		if err != nil {
			t.Fatalf("checking milestone %q in repo %q: %v", expectedMilestone, *repo, err)
		}
		if !exists {
			t.Fatalf("milestone %q does not exist or is not open in repo %q", expectedMilestone, *repo)
		}
	})
}
