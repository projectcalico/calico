// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package outputs

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

const (
	releaseNoteRequiredLabel = "release-note-required"
	closedState              = issueState("closed")
	openState                = issueState("open")
)

var (
	//go:embed templates/release-note.md.gotmpl
	releaseNoteTemplate string
	repos               = []string{utils.CalicoRepoName, utils.BirdRepoName}
)

type issueState string

// ReleaseNoteIssueData represents the data for an release note issue
type ReleaseNoteIssueData struct {
	ID     int
	Note   string
	Repo   string
	URL    string
	Author string
}

// ReleaseNoteData represents the data for release notes
type ReleaseNoteData struct {
	Date         string
	BugFixes     []*ReleaseNoteIssueData
	OtherChanges []*ReleaseNoteIssueData
}

// milestoneNumber returns the milestone number for a given milestone
func milestoneNumber(client *github.Client, owner, repo, milestone string, opts *github.MilestoneListOptions) (int, error) {
	for {
		milestones, resp, err := client.Issues.ListMilestones(context.Background(), owner, repo, opts)
		if err != nil {
			return -1, err
		}
		for _, m := range milestones {
			if m.GetTitle() == milestone {
				return m.GetNumber(), nil
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return -1, fmt.Errorf("milestone not found")
}

// prIssuesByRepo returns all the PR issues for a given repo
func prIssuesByRepo(client *github.Client, owner, repo string, opts *github.IssueListByRepoOptions) ([]*github.Issue, error) {
	prIssues := []*github.Issue{}
	for {
		issues, resp, err := client.Issues.ListByRepo(context.Background(), owner, repo, opts)
		if err != nil {
			return nil, err
		}
		for _, issue := range issues {
			if issue.IsPullRequest() {
				prIssues = append(prIssues, issue)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return prIssues, nil
}

// extractReleaseNoteFromIssue extracts release notes from an issue.
// It looks for the release note block in the issue body and returns the content
// between the start and end markers.
func extractReleaseNoteFromIssue(issue *github.Issue) ([]string, error) {
	body := issue.GetBody()
	pattern := "\\`\\`\\`release-note\\r?\\n(.*)\\r?\\n\\`\\`\\`"
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return []string{issue.GetTitle()}, fmt.Errorf("no release notes found")
	}
	var notes []string
	for _, match := range matches {
		if len(match) > 1 {
			notes = append(notes, match[1])
		}
	}
	return notes, nil
}

// extractReleaseNote extracts release notes from a list of issues
func extractReleaseNote(repo string, issues []*github.Issue) ([]*ReleaseNoteIssueData, error) {
	issueDataList := []*ReleaseNoteIssueData{}
	for _, issue := range issues {
		notes, err := extractReleaseNoteFromIssue(issue)
		if err != nil && len(notes) == 0 {
			logrus.WithError(err).Errorf("Failed to extract release notes for issue %d", issue.GetNumber())
			return nil, err
		}
		for _, note := range notes {
			note = strings.TrimSpace(note)
			if note == "TBD" {
				logrus.WithFields(logrus.Fields{
					"url":    issue.GetHTMLURL(),
					"author": issue.GetUser().GetLogin(),
				}).Warnf("Release note is TBD, please update the issue")
			}
			issueData := &ReleaseNoteIssueData{
				ID:     issue.GetNumber(),
				Note:   note,
				Repo:   repo,
				URL:    issue.GetHTMLURL(),
				Author: issue.GetUser().GetLogin(),
			}
			issueDataList = append(issueDataList, issueData)
		}
	}
	return issueDataList, nil
}

// outputReleaseNotes outputs the release notes to a file
func outputReleaseNotes(issueDataList []*ReleaseNoteIssueData, outputFilePath string) error {
	dir := filepath.Dir(outputFilePath)
	if err := os.MkdirAll(dir, utils.DirPerms); err != nil {
		logrus.WithError(err).Errorf("Failed to create release notes folder %s", dir)
		return err
	}
	logrus.WithField("template", releaseNoteTemplate).Debug("Parsing release note template")
	tmpl, err := template.New("release-note").Parse(releaseNoteTemplate)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse release note template")
		return err
	}
	logrus.Debug("Generating release notes from template")
	date := time.Now().Format("02 Jan 2006")
	data := &ReleaseNoteData{
		Date:         date,
		OtherChanges: issueDataList,
	}
	releaseNotedFile, err := os.Create(outputFilePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to create release notes file")
		return err
	}
	defer releaseNotedFile.Close()
	if err := tmpl.Execute(releaseNotedFile, data); err != nil {
		logrus.WithError(err).Error("Failed to execute release note template")
		return err
	}
	return nil
}

// ReleaseNotes generates release notes for a milestone
// and outputs it to a file in <outputDir>/release-notes/<milestone>-release-notes.md
func ReleaseNotes(owner, githubToken, repoRootDir, outputDir string, ver version.Version) (string, error) {
	if githubToken == "" {
		return "", fmt.Errorf("github token not set, set GITHUB_TOKEN environment variable")
	}
	if outputDir == "" {
		logrus.Warn("No directory is set, using current directory")
		outputDir = "."
	}
	logrus.Infof("Generating release notes for %s", ver.FormattedString())
	milestone := ver.Milestone(utils.CalicoProductName())
	githubClient := github.NewTokenClient(context.Background(), githubToken)
	releaseNoteDataList := []*ReleaseNoteIssueData{}
	opts := &github.MilestoneListOptions{
		State: string(openState),
	}
	for _, repo := range repos {
		milestoneNumber, error := milestoneNumber(githubClient, owner, repo, milestone, opts)
		if error != nil {
			logrus.WithError(error).Warnf("Failed to retrieve milestone for %s", repo)
			continue
		}
		opts := &github.IssueListByRepoOptions{
			Milestone: strconv.Itoa(milestoneNumber),
			State:     string(closedState),
			Labels:    []string{releaseNoteRequiredLabel},
		}
		logrus.WithField("repo", repo).Debug("Getting issues")
		prIssues, err := prIssuesByRepo(githubClient, owner, repo, opts)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to get issues for %s", repo)
			return "", err
		}
		relNoteDataList, err := extractReleaseNote(repo, prIssues)
		if err != nil {
			logrus.WithError(err).Error("Failed to extract release notes")
			return "", err
		}
		releaseNoteDataList = append(releaseNoteDataList, relNoteDataList...)
	}
	if len(releaseNoteDataList) == 0 {
		logrus.WithField("milestone", milestone).Error("No issues found for milestone")
		return "", fmt.Errorf("no issues found for milestone %s", milestone)
	}
	releaseNoteFilePath := filepath.Join(outputDir, fmt.Sprintf("%s-release-notes.md", ver.FormattedString()))
	if err := outputReleaseNotes(releaseNoteDataList, releaseNoteFilePath); err != nil {
		logrus.WithError(err).Error("Failed to output release notes")
		return "", err
	}
	return releaseNoteFilePath, nil
}
