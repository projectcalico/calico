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

package command

import (
	"fmt"
	"strings"
)

// Git runs a git command and returns trimmed stdout.
func Git(args ...string) (string, error) {
	return Run("git", args, nil)
}

// GitInDir runs a git command in the given directory and returns trimmed stdout.
func GitInDir(dir string, args ...string) (string, error) {
	return RunInDir(dir, "git", args, nil)
}

// GitDir returns the repo root directory.
func GitDir() (string, error) {
	return Git("rev-parse", "--show-toplevel")
}

// GitBranch returns the current git branch.
func GitBranch() (string, error) {
	return Git("branch", "--show-current")
}

// GitVersion returns the current git version using describe with long format and dirty flag.
func GitVersion() (string, error) {
	return Git("describe", "--tags", "--always", "--long", "--abbrev=12", "--dirty")
}

// GitShowFile reads a file from a specific git ref.
func GitShowFile(ref, path string) (string, error) {
	return Git("show", fmt.Sprintf("%s:%s", ref, path))
}

// GitLsRemote runs git ls-remote with the provided arguments.
func GitLsRemote(remote, ref string, flags ...string) (string, error) {
	args := append([]string{"ls-remote"}, flags...)
	args = append(args, remote, ref)
	return Git(args...)
}

// GitLsRemoteHeads runs git ls-remote --heads for a branch.
func GitLsRemoteHeads(remote, branch string) (string, error) {
	return GitLsRemote(remote, branch, "--heads")
}

// GitLsRemoteTags runs git ls-remote --tags for a tag.
func GitLsRemoteTags(remote, tag string) (string, error) {
	return GitLsRemote(remote, tag, "--tags")
}

// GitRefExistsInRemote checks if a ref exists in git ls-remote output.
func GitRefExistsInRemote(lsRemoteOutput, ref string) bool {
	for _, line := range strings.Split(lsRemoteOutput, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// ls-remote output format: <hash>\trefs/heads/<name> or refs/tags/<name>
		remoteRef := parts[1]
		// Strip known prefixes to get the full ref name (preserving slashes in ref names)
		name := remoteRef
		for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
			if trimmed, ok := strings.CutPrefix(remoteRef, prefix); ok {
				name = trimmed
				break
			}
		}
		if name == ref {
			return true
		}
	}
	return false
}

// GitHubMilestoneOpen reports whether a GitHub milestone with the given title exists and is open in the specified repo.
// The repo must be in "owner/name" format (e.g., "tigera/operator").
func GitHubMilestoneOpen(repo, milestone string) (bool, error) {
	out, err := Run("gh", []string{
		"api",
		"--paginate",
		fmt.Sprintf("/repos/%s/milestones?state=open&per_page=100", repo),
		"--jq", fmt.Sprintf(".[] | select(.title==%q) | .title", milestone),
	}, nil)
	if err != nil {
		return false, fmt.Errorf("listing milestones for %s: %w", repo, err)
	}
	return out == milestone, nil
}
