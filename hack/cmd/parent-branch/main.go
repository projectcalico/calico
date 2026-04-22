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
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	releasePrefix string
	gitRepoSlug   string
	verbose       bool
)

func main() {

	rootCmd := &cobra.Command{
		Use:   "parent-branch",
		Short: "Detect the parent release branch for the current git branch",
		Long: `Detects the parent release branch by first trying version-file based detection
(calico/_data/versions.yml) and then falling back to merge-base comparison
across remote release branches.`,
		SilenceUsage: true,
		RunE:         run,
	}

	rootCmd.Flags().StringVar(&releasePrefix, "release-prefix", releasePrefix, "Prefix for release branch names")
	rootCmd.Flags().StringVar(&gitRepoSlug, "git-repo-slug", gitRepoSlug, "GitHub repo slug to find the remote")
	rootCmd.Flags().BoolVar(&verbose, "debug", false, "Enable debug output")

	log.SetOutput(os.Stderr)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) error {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Debugf("Starting detection with release prefix `%s`, repo slug `%s`", releasePrefix, gitRepoSlug)
	log.Debug("Trying to detect base branch by looking for most similar branch")

	// Find the appropriate remote by matching the repo slug in git remote -v output.
	remote, err := findRemote(gitRepoSlug)
	if err != nil {
		return err
	}

	// If running in CI, fix remote fetch configs and fetch all.
	if _, ok := os.LookupEnv("CI"); ok {
		log.Debug("Running in CI, so we're inspecting the git remotes")
		if err := fixCIRemotes(); err != nil {
			return err
		}
		log.Debug("Fetching all remotes")
		if _, err := runGit("fetch", "--all", "--quiet"); err != nil {
			return fmt.Errorf("git fetch --all failed: %w", err)
		}
	}

	log.Debugf("Git remote: %s -> %s", gitRepoSlug, remote)

	// Try version-file strategy.
	toplevel, err := runGit("rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("failed to find git toplevel: %w", err)
	}
	versionsFile := toplevel + "/calico/_data/versions.yml"

	if _, statErr := os.Stat(versionsFile); statErr == nil {
		result, found, err := tryVersionFileStrategy(versionsFile, remote)
		if err != nil {
			return err
		}
		if found {
			fmt.Println(result)
			return nil
		}
	}

	// See if we can guess it from the most recent Git tag
	result, found, err := tryGitTagStrategy(remote)
	if err != nil {
		return err
	}
	if found {
		fmt.Println(result)
		return nil
	}

	// Fall back to merge-base strategy.
	result, err = mergeBaseStrategy(remote)
	if err != nil {
		return err
	}
	fmt.Println(result)
	return nil
}

// findRemote finds the git remote name that matches the given repo slug.
func findRemote(slug string) (string, error) {
	output, err := runGit("remote", "-v")
	if err != nil {
		return "", fmt.Errorf("git remote -v failed: %w", err)
	}

	// Match patterns like:
	//   proto://github.com/foo/bar.git
	//   git@github.com:foo/bar.git
	// The slug must appear after a separator (: or /) to avoid partial matches.
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "(fetch)") {
			// Check for [:/]slug pattern.
			if strings.Contains(line, "/"+slug) || strings.Contains(line, ":"+slug) {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					return fields[0], nil
				}
			}
		}
	}
	return "", fmt.Errorf("could not detect a git remote for %s", slug)
}

// fixCIRemotes ensures all remotes are configured to fetch all branches.
func fixCIRemotes() error {
	output, err := runGit("remote")
	if err != nil {
		return fmt.Errorf("git remote failed: %w", err)
	}
	for _, r := range strings.Split(strings.TrimSpace(output), "\n") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		fetchConfig, err := runGit("config", "get", "remote."+r+".fetch")
		if err != nil || !strings.Contains(fetchConfig, "*") {
			log.Debugf("Remote %s doesn't seem to be configured to fetch all branches; fixing...", r)
			if _, err := runGit("config", "remote."+r+".fetch", "+refs/heads/*:refs/remotes/"+r+"/*"); err != nil {
				return fmt.Errorf("failed to update fetch config for remote %s: %w", r, err)
			}
		} else {
			log.Debugf("Remote %s seems to be configured to fetch all branches", r)
		}
	}
	return nil
}

// tryVersionFileStrategy attempts to find the parent branch using the version
// from calico/_data/versions.yml.
func tryVersionFileStrategy(versionsFile, remote string) (string, bool, error) {
	log.Debug("Trying to detect base branch by looking at the version in calico/_data/versions.yml")

	data, err := os.ReadFile(versionsFile)
	if err != nil {
		return "", false, fmt.Errorf("failed to read versions file: %w", err)
	}

	var versions []struct {
		Title string `yaml:"title"`
	}
	if err := yaml.Unmarshal(data, &versions); err != nil {
		return "", false, fmt.Errorf("failed to parse versions file: %w", err)
	}
	if len(versions) == 0 || versions[0].Title == "" {
		log.Debug("No version found in versions file")
		return "", false, nil
	}
	version := versions[0].Title
	return tryVersionStrategy(version, remote)
}

func tryGitTagStrategy(remote string) (string, bool, error) {
	log.Debug("Trying to detect base branch by guessing based on the most recent git tag")
	recentTag, err := runGit("describe", "--tags", "--abbrev=0")
	if err != nil {
		log.Infof("Failed to get the most recent git tag: %s", err)
		return "", false, nil
	}
	log.Debugf("Found git tag `%s`, trying to parse it", recentTag)
	return tryVersionStrategy(recentTag, remote)
}

func tryVersionStrategy(version, remote string) (string, bool, error) {
	// Extract major.minor from version like "v3.22.3"
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		log.Debugf("Version %q doesn't have major.minor format", version)
		return "", false, nil
	}
	versionBase := parts[0] + "." + parts[1]

	constructedBranch := strings.TrimSuffix(releasePrefix, "v") + versionBase

	log.Debugf("Found version `%s`, looking for release branch %s", version, constructedBranch)

	currentBranch, _ := runGit("branch", "--show-current")

	// Are we on the branch that we want?
	if currentBranch == constructedBranch {
		log.Debugf("We're on branch %s, using that as our upstream", constructedBranch)
		upstream, err := runGit("rev-parse", "--abbrev-ref", currentBranch+"@{upstream}")
		if err != nil {
			return "", false, fmt.Errorf("failed to find upstream for %s: %w", currentBranch, err)
		}
		return upstream, true, nil
	}

	// Check for a local branch.
	log.Debugf("Checking for a local branch %s", constructedBranch)
	if _, err := runGit("rev-parse", "--verify", "--quiet", constructedBranch); err == nil {
		upstream, err := runGit("rev-parse", "--abbrev-ref", constructedBranch+"@{upstream}")
		if err != nil {
			return "", false, fmt.Errorf("failed to find upstream for %s: %w", constructedBranch, err)
		}
		return upstream, true, nil
	}

	// Check for a remote branch.
	remoteBranch := remote + "/" + constructedBranch
	log.Debugf("Checking for a remote branch %s", remoteBranch)
	if result, err := runGit("rev-parse", "--abbrev-ref", "--quiet", remoteBranch); err == nil && result != "" {
		return result, true, nil
	}

	log.Debugf("We weren't able to find a branch based off the version %s", version)
	return "", false, nil
}

// mergeBaseStrategy finds the remote branch with the smallest merge-base
// distance to HEAD.
func mergeBaseStrategy(remote string) (string, error) {
	log.Debug("Checking remote branches for smallest merge-base difference:")

	output, err := runGit("for-each-ref", "--format=%(refname:short)", "refs/remotes/"+remote)
	if err != nil {
		return "", fmt.Errorf("failed to list remote refs: %w", err)
	}

	// Match master or release-v branches (e.g., release-v3.22).
	pattern := regexp.MustCompile(
		`^` + regexp.QuoteMeta(remote) + `/master$` +
			`|^` + regexp.QuoteMeta(remote) + `/` + regexp.QuoteMeta(releasePrefix) + `[3-9]\.[2-9]`)

	bestCount := 1000000
	best := ""

	for _, ref := range strings.Split(output, "\n") {
		ref = strings.TrimSpace(ref)
		if ref == "" || !pattern.MatchString(ref) {
			continue
		}

		mergeBase, err := runGit("merge-base", ref, "HEAD")
		if err != nil {
			log.Debugf("Skipping ref %s as we couldn't find a merge-base", ref)
			continue
		}

		log.Debugf("Checking branch %s", ref)
		countStr, err := runGit("rev-list", "--count", mergeBase+"..HEAD")
		if err != nil {
			log.Debugf("Skipping ref %s: rev-list failed: %v", ref, err)
			continue
		}

		count, err := strconv.Atoi(countStr)
		if err != nil {
			log.Debugf("Skipping ref %s: couldn't parse count %q", ref, countStr)
			continue
		}

		if count < bestCount {
			log.Debugf("Updating best ref to %s with count of %d", ref, count)
			bestCount = count
			best = ref
		}

	}
	if best == "" {
		log.Errorf("No suitable remote branches found for %s", remote)
		return "", fmt.Errorf("no suitable remote branches found for %s", remote)
	}

	log.Debugf("Found best result %s with a difference of %d", best, bestCount)
	return best, nil
}

// runGit executes a git command and returns its trimmed stdout.
// It is a variable so that tests can replace it with a mock.
var runGit = runGitReal

func runGitReal(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
