package docs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/sirupsen/logrus"
)

const (
	releaseNoteLabel        = "release-note-required"
	releaseNotesFolder      = "release-notes"
	releaseNoteTemplatePath = "/fixham/assets/release-note.md.tmpl"
)

var (
	repos = []string{"calico", "bird"}
)

// ReleaseNoteIssueData represents the data for an release note issue
type ReleaseNoteIssueData struct {
	ID     int
	Note   string
	Repo   string
	URL    string
	Author string
}

type ReleaseNoteData struct {
	Date         string
	BugFixes     []*ReleaseNoteIssueData
	OtherChanges []*ReleaseNoteIssueData
}

func milestoneNumber(client *github.Client, owner, repo, milestone string) (int, error) {
	for {
		milestones, resp, err := client.Issues.ListMilestones(context.Background(), owner, repo, nil)
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
	}
	return -1, fmt.Errorf("milestone not found")
}

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

func releaseNoteFilePath(dir, milestone string) string {
	version := strings.Split(milestone, " ")[1]
	return fmt.Sprintf("%s/%s/%s-release-notes.md", dir, releaseNotesFolder, version)
}

func extractReleaseNoteFromIssue(issue *github.Issue) ([]string, error) {
	body := issue.GetBody()
	startMarker := "```release-note"
	endMarker := "```"
	startIndex := strings.Index(body, startMarker)
	if startIndex == -1 {
		return []string{issue.GetTitle()}, fmt.Errorf("start marker not found")
	}
	startIndex += len(startMarker)
	endIndex := strings.Index(body[startIndex:], endMarker)
	if endIndex == -1 {
		return nil, fmt.Errorf("end marker not found")
	}
	notes := strings.TrimSpace(body[startIndex : startIndex+endIndex])
	if len(notes) == 0 {
		return []string{issue.GetTitle()}, fmt.Errorf("no release notes found")
	}
	return strings.Split(notes, "\n"), nil
}

func extractReleaseNote(repo string, issues []*github.Issue) ([]*ReleaseNoteIssueData, error) {
	issueDataList := []*ReleaseNoteIssueData{}
	for _, issue := range issues {
		notes, err := extractReleaseNoteFromIssue(issue)
		if err != nil && len(notes) == 0 {
			logrus.WithError(err).Errorf("Failed to extract release notes for issue %d", issue.GetNumber())
			return nil, err
		}
		for _, note := range notes {
			_note := strings.TrimSpace(note)
			if _note == "TBD" {
				logrus.WithFields(logrus.Fields{
					"url":    issue.GetHTMLURL(),
					"author": issue.GetUser().GetLogin(),
				}).Warnf("Release note is TBD, please update the issue")
			}
			issueData := &ReleaseNoteIssueData{
				ID:     issue.GetNumber(),
				Note:   _note,
				Repo:   repo,
				URL:    issue.GetHTMLURL(),
				Author: issue.GetUser().GetLogin(),
			}
			issueDataList = append(issueDataList, issueData)
		}
	}
	return issueDataList, nil
}

func outputReleaseNotes(issueDataList []*ReleaseNoteIssueData, templateFilePath, outputFilePath string) error {
	dir := filepath.Dir(outputFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logrus.WithError(err).Errorf("Failed to create release notes folder %s", dir)
		return err
	}
	releaseNoteTemplate, err := os.ReadFile(templateFilePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to read release note template")
		return err
	}
	tmpl, err := template.New("release-note").Parse(string(releaseNoteTemplate))
	if err != nil {
		logrus.WithError(err).Error("Failed to parse release note template")
		return err
	}
	logrus.Info("Generating release notes")
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

// GenerateReleaseNotes generates release notes for a milestone
// and outputs it to a file in <outputDir>/release-notes/<milestone>-release-notes.md
func GenerateReleaseNotes(owner, milestone, githubToken, repoRootDir, outputDir string) (string, error) {
	if githubToken == "" {
		return "", fmt.Errorf("github token not set, set GITHUB_TOKEN environment variable")
	}
	if milestone == "" {
		return "", fmt.Errorf("milestone not set")
	}
	if outputDir == "" {
		logrus.Warn("No directory is set, using current directory")
		outputDir = "."
	}
	githubClient := github.NewTokenClient(context.Background(), githubToken)
	issueDataList := []*ReleaseNoteIssueData{}
	for _, repo := range repos {
		milestoneNumber, error := milestoneNumber(githubClient, owner, repo, milestone)
		if error != nil {
			logrus.WithError(error).Warnf("Failed to retrieve milestone for %s", repo)
			continue
		}
		opts := &github.IssueListByRepoOptions{
			Milestone: strconv.Itoa(milestoneNumber),
			State:     "closed",
			Labels:    []string{releaseNoteLabel},
		}
		logrus.WithField("repo", repo).Debug("Getting issues")
		prIssues, err := prIssuesByRepo(githubClient, owner, repo, opts)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to get issues for %s", repo)
			return "", err
		}
		_issueDataList, err := extractReleaseNote(repo, prIssues)
		if err != nil {
			logrus.WithError(err).Error("Failed to extract release notes")
			return "", err
		}
		issueDataList = append(issueDataList, _issueDataList...)
	}
	if len(issueDataList) == 0 {
		logrus.WithField("milestone", milestone).Error("No issues found for milestone")
		return "", fmt.Errorf("no issues found for milestone %s", milestone)
	}
	releaseNoteFilePath := releaseNoteFilePath(outputDir, milestone)
	if err := outputReleaseNotes(issueDataList, repoRootDir+"/"+releaseNoteTemplatePath, releaseNoteFilePath); err != nil {
		logrus.WithError(err).Error("Failed to output release notes")
		return "", err
	}
	return releaseNoteFilePath, nil
}
