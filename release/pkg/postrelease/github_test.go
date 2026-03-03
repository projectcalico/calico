package postrelease

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-github/v53/github"

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

const (
	calicoctlBinaryName = "calicoctl"
	metadataFileName    = "metadata.yaml"
)

func calicoctlBinaryList() []string {
	var binaries []string
	for _, arch := range linuxArches {
		binaries = append(binaries, fmt.Sprintf("%s-linux-%s", calicoctlBinaryName, arch))
	}
	for _, arch := range darwinArches {
		binaries = append(binaries, fmt.Sprintf("%s-darwin-%s", calicoctlBinaryName, arch))
	}
	binaries = append(binaries, fmt.Sprintf("%s-windows-amd64.exe", calicoctlBinaryName))
	return binaries
}

func githubClient() *github.Client {
	cli := github.NewClient(http.DefaultClient)
	if githubToken != "" {
		cli = github.NewTokenClient(context.Background(), githubToken)
	}
	return cli
}

func TestGitHubRelease(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	release, resp, err := githubClient().Repositories.GetReleaseByTag(context.Background(), githubOrg, githubRepo, releaseVersion)
	if err != nil {
		t.Fatalf("failed to get release %s: %v", releaseVersion, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to get release %s: %v", releaseVersion, resp.Status)
	}

	t.Run("check release assets", func(t *testing.T) {
		expectedAssets := append(calicoctlBinaryList(),
			metadataFileName,
			"install-calico-windows.ps1",
			fmt.Sprintf("calico-windows-%s.zip", releaseVersion),
			fmt.Sprintf("release-%s.tgz", releaseVersion),
			fmt.Sprintf("tigera-operator-%s.tgz", releaseVersion),
			"SHA256SUMS",
			"ocp.tgz",
			"LICENSE",
		)
		actualAssets := getAssets(release)
		if diff := cmp.Diff(expectedAssets, actualAssets, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
			t.Errorf("release assets mismatch (-expected +actual):\n%s", diff)
		}
	})
}

func getAssets(release *github.RepositoryRelease) []string {
	var assets []string
	for _, asset := range release.Assets {
		assets = append(assets, asset.GetName())
	}
	return assets
}

func TestGitHubReleaseNotes(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	_, _, resp, err := githubClient().Repositories.GetContents(context.Background(), githubOrg, githubRepo, fmt.Sprintf("release-notes/%s-release-notes.md", releaseVersion), &github.RepositoryContentGetOptions{
		Ref: releaseVersion,
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to get release notes %s: %v", releaseVersion, err)
	}
}

func TestGitHubMilestone(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	ver := version.New(releaseVersion)
	nextVer, err := ver.NextReleaseVersion()
	if err != nil {
		t.Fatalf("failed to get next release version: %v", err)
	}
	for _, tt := range []struct {
		milestone      string
		expectedStated string
	}{
		{milestone: fmt.Sprintf("%s %s", utils.ProductName, ver.FormattedString()), expectedStated: "closed"},
		{milestone: fmt.Sprintf("%s %s", utils.ProductName, nextVer.FormattedString()), expectedStated: "open"},
	} {
		t.Run(tt.milestone, func(t *testing.T) {
			milestones, resp, err := githubClient().Issues.ListMilestones(context.Background(), githubOrg, githubRepo, &github.MilestoneListOptions{
				State:     tt.expectedStated,
				Direction: "desc",
				ListOptions: github.ListOptions{
					PerPage: 100,
					Page:    1,
				},
			})
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("failed to list milestones: %v", err)
			}
			selected := slices.Collect(func(yield func(*github.Milestone) bool) {
				for _, m := range milestones {
					if m.GetTitle() == tt.milestone {
						yield(m)
					}
				}
			})
			if len(selected) == 0 {
				t.Fatalf("failed to find milestone %s", tt.milestone)
			}
			actualState := selected[0].GetState()
			if actualState != tt.expectedStated {
				t.Fatalf(`expected "%s" milestone to be %s but found %s`, tt.milestone, tt.expectedStated, actualState)
			}
		})
	}
}
