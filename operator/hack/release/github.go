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
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	"github.com/google/go-github/v53/github"
	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/tigera/operator/hack/release/internal/versions"
)

//go:embed templates/release-notes.md.gotmpl
var releaseNoteTemplate string

// Issue labels
const (
	releaseNoteRequiredLabel = "release-note-required"
	kindLabelPrefix          = "kind/"
	issueKindBugFix          = issueKind("kind/bug")
	issueKindEnhancement     = issueKind("kind/enhancement")
)

// State of issues and milestones
const (
	closedState = "closed"
	openState   = "open"
	allState    = "all"
)

var (
	ErrGitHubReleaseExists   = errors.New("GitHub release already exists")
	ErrNoGitHubReleaseExists = errors.New("GitHub release does not exist")
)

type issueKind string

// ReleaseNoteItem represents a single release note extracted from an issue or PR.
type ReleaseNoteItem struct {
	ID     int    // Issue or PR number
	Note   string // The text of the release note
	URL    string // The URL to the issue or PR
	Author string // The author of the issue or PR
}

func (r ReleaseNoteItem) String() string {
	return fmt.Sprintf("%s [#%d](%s) (@%s)", r.Note, r.ID, r.URL, r.Author)
}

// ReleaseNoteData holds categorized release notes for a release.
type ReleaseNoteData struct {
	Date         string
	Enhancements []ReleaseNoteItem
	BugFixes     []ReleaseNoteItem
	OtherChanges []ReleaseNoteItem
	Versions     map[string]string // Calico and Enterprise versions
}

// GithubRelease represents a GitHub-hosted release of the operator.
type GithubRelease struct {
	Org               string                    // GitHub organization
	Repo              string                    // GitHub repository
	Version           string                    // Release version
	githubClient      *github.Client            // GitHub API client
	githubRepoRelease *github.RepositoryRelease // Cached GitHub release
	milestone         *github.Milestone         // Cached GitHub milestone
}

// Setup the GitHub client for this release using the provided token.
func (r *GithubRelease) setupClient(ctx context.Context, token string) error {
	if r.githubClient != nil {
		return nil
	}
	if token == "" {
		return fmt.Errorf("GitHub token is required to create GitHub client")
	}
	r.githubClient = github.NewTokenClient(ctx, token)
	return nil
}

// Get the milestone for this release's version.
func (r *GithubRelease) getMilestone(ctx context.Context) (*github.Milestone, error) {
	if r.milestone != nil {
		return r.milestone, nil
	}
	opts := &github.MilestoneListOptions{
		State: string(allState),
	}
	for {
		milestones, resp, err := r.githubClient.Issues.ListMilestones(ctx, r.Org, r.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, m := range milestones {
			if m.GetTitle() == r.Version {
				r.milestone = m
				return m, nil
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil, fmt.Errorf("milestone %q not found in %s/%s", r.Version, r.Org, r.Repo)
}

// Close the milestone for this release's version.
func (r *GithubRelease) closeMilestone(ctx context.Context) error {
	milestone, err := r.getMilestone(ctx)
	if err != nil {
		return err
	}
	_, _, err = r.githubClient.Issues.EditMilestone(ctx, r.Org, r.Repo, milestone.GetNumber(), &github.Milestone{
		State: github.String(closedState),
	})
	if err != nil {
		return fmt.Errorf("closing %s milestone (%d): %w", milestone.GetTitle(), milestone.GetNumber(), err)
	}
	return nil
}

func ReleaseNotesFilePath(outputDir, version string) string {
	return fmt.Sprintf("%s/%s-release-notes.md", outputDir, version)
}

// Generate release notes for this release and write them to the specified output directory.
// If outputDir is empty, write to stdout.
// If useLocal is true, generate release notes based on local versions files
// instead of using versions files from GitHub tag corresponding to the release version.
func (r *GithubRelease) GenerateNotes(ctx context.Context, outputDir string, useLocal bool) error {
	var writer io.Writer
	var writeLogger *logrus.Entry
	if outputDir == "" {
		logrus.Warn("No output dir specified, will output release notes to stdout")
		writer = os.Stdout
		writeLogger = logrus.WithField("output", "stdout")
	} else {
		if err := os.MkdirAll(outputDir, os.ModeDir); err != nil {
			logrus.WithError(err).Errorf("Failed to create release notes folder %s", outputDir)
			return err
		}
		f, err := os.Create(ReleaseNotesFilePath(outputDir, r.Version))
		if err != nil {
			logrus.WithError(err).Errorf("Failed to create release notes file in %s", outputDir)
			return err
		}
		defer func() { _ = f.Close() }()
		writer = f
		writeLogger = logrus.WithField("output", f.Name())
	}
	noteData, err := r.collectReleaseNotes(ctx, useLocal)
	if err != nil {
		return fmt.Errorf("collecting release notes: %s", err)
	}
	tmpl, err := template.New("release-note").Parse(releaseNoteTemplate)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse release note template")
		return err
	}
	writeLogger.Debug("Writing release notes")
	if err := tmpl.Execute(writer, noteData); err != nil {
		logrus.WithError(err).Error("Failed to execute release note template")
		return err
	}
	return nil
}

// Get all merged PRs (as issues) with the given milestone number that have the "release-note-required" label.
func (r *GithubRelease) releaseNoteIssues(ctx context.Context) ([]*github.Issue, error) {
	milestone, err := r.getMilestone(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieving milestone for version %s: %w", r.Version, err)
	}
	if milestone.GetState() != string(closedState) {
		logrus.WithField("milestone", milestone.GetTitle()).Warn("Milestone is not closed")
	}
	opts := &github.IssueListByRepoOptions{
		Milestone: strconv.Itoa(milestone.GetNumber()),
		State:     string(allState),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
		Labels: []string{releaseNoteRequiredLabel},
	}
	filter := func(issue *github.Issue) (bool, error) {
		if !issue.IsPullRequest() {
			return false, nil
		}
		pr, _, err := r.githubClient.PullRequests.Get(ctx, r.Org, r.Repo, issue.GetNumber())
		if err != nil {
			return false, fmt.Errorf("retrieving PR for issue %d: %w", issue.GetNumber(), err)
		}
		return pr.Merged != nil && *pr.Merged, nil
	}
	relIssues, err := githubIssues(ctx, r.githubClient, r.Org, r.Repo, opts, filter)
	if err != nil {
		return nil, fmt.Errorf("retrieving release note issues: %w", err)
	}
	return relIssues, nil
}

// Get all open issues in this release using an optional filter function that may return an error.
func (r *GithubRelease) openIssues(ctx context.Context, filter func(*github.Issue) (bool, error)) ([]*github.Issue, error) {
	milestone, err := r.getMilestone(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieving milestone for version %s: %w", r.Version, err)
	}
	opts := &github.IssueListByRepoOptions{
		Milestone: strconv.Itoa(milestone.GetNumber()),
		State:     string(openState),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	return githubIssues(ctx, r.githubClient, r.Org, r.Repo, opts, filter)
}

// Determine the kind of issue based on its labels.
// If no kind label is found, return "other".
func determineIssueKind(issue *github.Issue) issueKind {
	for _, label := range issue.Labels {
		if strings.HasPrefix(label.GetName(), kindLabelPrefix) {
			return issueKind(label.GetName())
		}
	}
	return issueKind("other")
}

// Extract release note text from the issue body using code blocks marked with "release-note".
// If no such block is found, use the issue title as the release note.
// If the block contains "TBD", it uses the issue title instead.
// If multiple release-note blocks are found, all non-TBD content is included.
func extractReleaseNoteFromIssue(issue *github.Issue) []string {
	body := issue.GetBody()
	pattern := "\\`\\`\\`release-note(?s)(.*?)\\`\\`\\`"
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		logrus.WithField("issue", issue.GetNumber()).Warn("No release note found in issue body, using issue title instead")
		return []string{issue.GetTitle()}
	}
	logrus.WithFields(logrus.Fields{
		"issue":   issue.GetNumber(),
		"matches": matches,
	}).Debug("Found release note in issue body")
	var notes []string
	for _, match := range matches {
		if len(match) < 2 {
			logrus.WithField("issue", issue.GetNumber()).Warn("No release note content found in matched block")
			continue
		}
		for _, m := range match[1:] {
			for _, line := range strings.Split(m, "\n") {
				trimmedLine := strings.TrimSpace(line)
				if trimmedLine == "TBD" {
					logrus.WithField("issue", issue.GetNumber()).Warn("Release note marked as TBD, not including in release notes")
					continue
				}
				if trimmedLine != "" {
					notes = append(notes, trimmedLine)
				}
			}
		}
	}
	if len(notes) == 0 {
		logrus.WithField("issue", issue.GetNumber()).Warn("No release note content found after processing matched block, using issue title instead")
		return []string{issue.GetTitle()}
	}
	return notes
}

// Gather release notes for this release's milestone.
// A release note is gathered from all merged PRs in the milestone that have the "release-note-required" label.
func (r *GithubRelease) collectReleaseNotes(ctx context.Context, local bool) (*ReleaseNoteData, error) {
	data := &ReleaseNoteData{
		Date: time.Now().Format("02 Jan 2006"), // assume today's date for the release.
	}
	dir, err := command.GitDir()
	if err != nil {
		return data, fmt.Errorf("getting git directory: %s", err)
	}
	var vers versions.Versions
	if local {
		vers, err = versions.ConfigVersions(dir)
	} else {
		vers, err = versions.GitRefConfigVersions(r.Version)
	}
	if err != nil {
		return data, fmt.Errorf("retrieving release versions: %s", err)
	}
	data.Versions = vers.ToMap()
	log := logrus.WithField("org", r.Org).WithField("repo", r.Repo).WithField("version", r.Version)
	issues, err := r.releaseNoteIssues(ctx)
	if err != nil {
		return data, err
	}
	if len(issues) == 0 {
		// If no merged PRs with release notes found, log a warning and return empty notes.
		// Sometimes releases may not have any release notes, but this is uncommon.
		log.Warnf("No merged PRs found with %q label", releaseNoteRequiredLabel)
		return data, nil
	}
	for _, issue := range issues {
		logrus.WithField("issue", issue.GetNumber()).Debug("Processing release note issue")
		kind := determineIssueKind(issue)
		notes := extractReleaseNoteFromIssue(issue)
		for _, note := range notes {
			switch kind {
			case issueKindBugFix:
				data.BugFixes = append(data.BugFixes, ReleaseNoteItem{
					ID:     issue.GetNumber(),
					Note:   note,
					URL:    issue.GetHTMLURL(),
					Author: issue.GetUser().GetLogin(),
				})
			case issueKindEnhancement:
				data.Enhancements = append(data.Enhancements, ReleaseNoteItem{
					ID:     issue.GetNumber(),
					Note:   note,
					URL:    issue.GetHTMLURL(),
					Author: issue.GetUser().GetLogin(),
				})
			default:
				data.OtherChanges = append(data.OtherChanges, ReleaseNoteItem{
					ID:     issue.GetNumber(),
					Note:   note,
					URL:    issue.GetHTMLURL(),
					Author: issue.GetUser().GetLogin(),
				})
			}
		}
	}

	return data, nil
}

// Check if a GitHub release already exists for this version.
// Since the release could already exist in draft, it uses the ListReleases instead of GetReleaseByTag.
// Cache the result for future calls.
func (r *GithubRelease) repoRelease(ctx context.Context) (*github.RepositoryRelease, error) {
	if r.githubRepoRelease != nil {
		return r.githubRepoRelease, nil
	}
	opts := &github.ListOptions{PerPage: 100}
	for {
		release, resp, err := r.githubClient.Repositories.ListReleases(ctx, r.Org, r.Repo, opts)
		if err != nil {
			return nil, fmt.Errorf("listing releases: %w", err)
		}
		for _, rel := range release {
			if rel.GetTagName() == r.Version {
				r.githubRepoRelease = rel
				break
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return r.githubRepoRelease, nil
}

// Create a new GitHub release.
func (r *GithubRelease) Create(ctx context.Context, isDraft, isPrerelease bool) error {
	// Check if release already exists
	if got, err := r.repoRelease(ctx); err != nil {
		return fmt.Errorf("checking if release exists: %w", err)
	} else if got != nil {
		logrus.Warnf("GitHub release already exists, update manually: %s", got.GetHTMLURL())
		return ErrGitHubReleaseExists
	}

	logrus.WithFields(logrus.Fields{
		"version":    r.Version,
		"draft":      isDraft,
		"prerelease": isPrerelease,
	}).Info("Creating GitHub release")

	// Generate release notes
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("operator-%s-*", r.Version))
	if err != nil {
		return fmt.Errorf("creating temporary directory for release notes: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	if err := r.GenerateNotes(ctx, tmpDir, false); err != nil {
		return fmt.Errorf("generating release notes for %s: %w", r.Version, err)
	}
	relNotesBytes, err := os.ReadFile(ReleaseNotesFilePath(tmpDir, r.Version))
	if err != nil {
		return fmt.Errorf("reading release notes file for %s: %w", r.Version, err)
	}

	release, _, err := r.githubClient.Repositories.CreateRelease(ctx, r.Org, r.Repo, &github.RepositoryRelease{
		TagName:    github.String(r.Version),
		Name:       github.String(r.Version),
		Body:       github.String(string(relNotesBytes)),
		Draft:      github.Bool(isDraft),
		Prerelease: github.Bool(isPrerelease),
		MakeLatest: r.makeLatest(ctx, isDraft, isPrerelease),
	})
	if err != nil {
		return fmt.Errorf("creating GitHub release for %s: %w", r.Version, err)
	}
	log := logrus.WithField("release", r.Version).WithField("url", release.GetHTMLURL())
	if isDraft {
		log.Info("GitHub release created in draft state, review and publish it manually")
		return nil
	}
	log.Info("GitHub release created")
	return nil
}

// Helper function to determine the value for MakeLatest option for GitHub releases.
// If the release is a draft or prerelease, it cannot be the latest release, so return false.
// Otherwise, compare with the current latest release and return true if this release's version is greater, false otherwise.
func (r *GithubRelease) makeLatest(ctx context.Context, isDraft, isPrerelease bool) *string {
	notLatest := github.String("false")
	if isDraft || isPrerelease {
		return notLatest
	}
	latestRelease, _, err := r.githubClient.Repositories.GetLatestRelease(ctx, r.Org, r.Repo)
	if err != nil {
		logrus.WithError(err).Warn("Failed to get latest release, defaulting to not making this release the latest")
		return notLatest
	}
	latestVersion, err := semver.ParseTolerant(latestRelease.GetTagName())
	if err != nil {
		logrus.WithError(err).Warn("Failed to parse latest release version, defaulting to not making this release the latest")
		return notLatest
	}
	thisVersion, err := semver.ParseTolerant(r.Version)
	if err != nil {
		logrus.WithError(err).Warn("Failed to parse current release version, defaulting to not making this release the latest")
		return notLatest
	}
	return github.String(strconv.FormatBool(thisVersion.GT(latestVersion)))
}

// Update an existing GitHub release.
func (r *GithubRelease) Update(ctx context.Context, isDraft, isPrerelease bool) error {
	if rel, err := r.repoRelease(ctx); err != nil {
		return fmt.Errorf("checking if release exists: %w", err)
	} else if rel == nil {
		return ErrNoGitHubReleaseExists
	}
	release, _, err := r.githubClient.Repositories.EditRelease(ctx, r.Org, r.Repo, r.githubRepoRelease.GetID(), &github.RepositoryRelease{
		Draft:      github.Bool(isDraft),
		Prerelease: github.Bool(isPrerelease),
		MakeLatest: r.makeLatest(ctx, isDraft, isPrerelease),
	})
	if err != nil {
		return fmt.Errorf("updating GitHub release for %s: %w", r.Version, err)
	}
	log := logrus.WithField("release", r.Version).WithField("url", release.GetHTMLURL())
	if isDraft {
		log.Info("GitHub release updated in draft state, review and publish it manually")
		return nil
	}
	log.Info("GitHub release updated")
	return nil
}

// Helper function to list GitHub issues based on the provided options and optional filter function.
// The filter may return an error which will be propagated to the caller.
func githubIssues(ctx context.Context, client *github.Client, org, repo string, opts *github.IssueListByRepoOptions, filter func(*github.Issue) (bool, error)) ([]*github.Issue, error) {
	issues := []*github.Issue{}
	errs := []error{}
	for {
		pageIssues, resp, err := client.Issues.ListByRepo(ctx, org, repo, opts)
		if err != nil {
			errs = append(errs, err)
			break
		}
		for _, issue := range pageIssues {
			if filter == nil {
				issues = append(issues, issue)
				continue
			}
			if ok, ferr := filter(issue); ferr != nil {
				errs = append(errs, ferr)
				continue
			} else if ok {
				issues = append(issues, issue)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if num := len(errs); num > 0 {
		return issues, fmt.Errorf("encountered %d error(s): %v", num, errs)
	}
	return issues, nil
}

// Create a new GitHub milestone with the given name.
func newGithubMilestone(ctx context.Context, githubClient *github.Client, org, repo, name string) (*github.Milestone, error) {
	milestone, _, err := githubClient.Issues.CreateMilestone(ctx, org, repo, &github.Milestone{
		Title: github.String(name),
		State: github.String(openState),
	})
	if err != nil {
		return nil, fmt.Errorf("creating next milestone %s: %w", name, err)
	}
	logrus.Debugf("Created new milestone %s (%d)", milestone.GetTitle(), milestone.GetNumber())
	return milestone, nil
}

// Batch update GitHub issues in parallel to set their milestone.
func updateGitHubIssues(ctx context.Context, githubClient *github.Client, org, repo string, issues []*github.Issue, request *github.IssueRequest) error {
	type issueUpdateResult struct {
		issueNumber int
		err         error
	}
	resultCh := make(chan issueUpdateResult, len(issues))

	for _, issue := range issues {
		go func(issue *github.Issue) {
			_, _, err := githubClient.Issues.Edit(ctx, org, repo, issue.GetNumber(), request)
			resultCh <- issueUpdateResult{issueNumber: issue.GetNumber(), err: err}
		}(issue)
	}

	var failedIssues []int
	for i := 0; i < len(issues); i++ {
		result := <-resultCh
		if result.err != nil {
			logrus.WithField("issue", result.issueNumber).WithError(result.err).Error("Failed to update issue")
			failedIssues = append(failedIssues, result.issueNumber)
		} else {
			logrus.WithField("issue", result.issueNumber).Debug("Updated issue successfully")
		}
	}

	if len(failedIssues) > 0 {
		return fmt.Errorf("failed to update issues: %s", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(failedIssues)), ", "), "[]"))
	}

	return nil
}

// Manage the stream milestone for the release version.
// It creates a new milestone for the next patch version in the stream
// and moves any open issues in the current milestone to it.
// Finally, it closes the current milestone if there are no open issues remaining.
func manageStreamMilestone(ctx context.Context, githubToken string) error {
	githubOrg := ctx.Value(githubOrgCtxKey).(string)
	githubRepo := ctx.Value(githubRepoCtxKey).(string)
	version := ctx.Value(versionCtxKey).(string)

	r := &GithubRelease{
		Org:     githubOrg,
		Repo:    githubRepo,
		Version: version,
	}
	if err := r.setupClient(ctx, githubToken); err != nil {
		return fmt.Errorf("setting up GitHub client: %w", err)
	}

	// Get milestone for the release version
	milestone, err := r.getMilestone(ctx)
	if err != nil {
		return fmt.Errorf("retrieving milestone for version %s: %w", version, err)
	}
	semVersion, err := semver.Parse(strings.TrimPrefix(version, "v"))
	if err != nil {
		return fmt.Errorf("parsing semantic version from %s: %w", version, err)
	}
	if err := semVersion.IncrementPatch(); err != nil {
		return fmt.Errorf("getting next version for %s: %w", version, err)
	}
	nextVersion := fmt.Sprintf("v%s", semVersion.String())
	nextMilestone, err := newGithubMilestone(ctx, r.githubClient, r.Org, r.Repo, nextVersion)
	if err != nil {
		return fmt.Errorf("creating next milestone %s: %w", nextVersion, err)
	}
	var filter func(*github.Issue) (bool, error)
	if headBranch := ctx.Value(headBranchCtxKey).(string); headBranch != "" {
		filter = func(issue *github.Issue) (bool, error) {
			if !issue.IsPullRequest() {
				return true, nil
			}
			pr, _, err := r.githubClient.PullRequests.Get(ctx, r.Org, r.Repo, issue.GetNumber())
			if err != nil {
				return false, fmt.Errorf("retrieving PR for issue %d: %w", issue.GetNumber(), err)
			}
			return pr.Head.GetRef() != headBranch, nil
		}
	}
	issues, err := r.openIssues(ctx, filter)
	if err != nil {
		return fmt.Errorf("retrieving open issues in %s milestone: %w", milestone.GetTitle(), err)
	}
	if len(issues) == 0 {
		return r.closeMilestone(ctx)
	}
	if err := updateGitHubIssues(ctx, r.githubClient, r.Org, r.Repo, issues, &github.IssueRequest{
		Milestone: github.Int(nextMilestone.GetNumber()),
	}); err != nil {
		return fmt.Errorf("moving issues from milestone %s to %s: %w", milestone.GetTitle(), nextMilestone.GetTitle(), err)
	}
	return r.closeMilestone(ctx)
}
