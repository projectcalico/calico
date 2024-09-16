// Package github contains functionality for interacting with the Github API
package github

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v63/github"
)

var githubToken = os.Getenv("GITHUB_TOKEN")

// GetGithubClient returns an instance of github.Client using a token from the environment.
func GetGithubClient() *github.Client {
	ghClient := github.NewClient(nil)
	if githubToken != "" {
		ghClient = ghClient.WithAuthToken(githubToken)
	}
	return ghClient
}

// GetProjectReleaseByTag fetches the release object for `releaseTag` from project `project`
func GetProjectReleaseByTag(project, releaseTag string) (*github.RepositoryRelease, error) {
	names := strings.Split(project, "/")
	orgName := names[0]
	projectName := names[1]

	ghClient := GetGithubClient()

	release, _, err := ghClient.Repositories.GetReleaseByTag(context.Background(), orgName, projectName, releaseTag)
	if err != nil {
		return nil, fmt.Errorf("could not get release %s from github project %s: %w", releaseTag, project, err)
	}

	return release, nil
}

// GetProjectReleaseArtifacts gets a list of release asset objects from a given release of a project
func GetProjectReleaseArtifacts(project, releaseTag string) ([]*github.ReleaseAsset, error) {
	var assets []*github.ReleaseAsset

	release, err := GetProjectReleaseByTag(project, releaseTag)
	if err != nil {
		return nil, fmt.Errorf("could not get artifacts for release %s from github project %s: %w", releaseTag, project, err)
	}

	assets = append(assets, release.Assets...)

	return assets, nil
}

// GetProjectReleaseArtifactNames gets a list of asset filenames for a given release of a project
func GetProjectReleaseArtifactNames(project, releaseTag string) ([]string, error) {
	var assetNames []string

	assets, err := GetProjectReleaseArtifacts(project, releaseTag)
	if err != nil {
		return nil, fmt.Errorf("could not get names for artifacts for release %s from github project %s: %w", releaseTag, project, err)
	}

	for _, assetObj := range assets {
		assetNames = append(assetNames, assetObj.GetName())
	}

	return assetNames, nil
}
