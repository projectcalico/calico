package github

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v63/github"
)

var GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")

func GetGithubClient() *github.Client {
	ghClient := github.NewClient(nil).WithAuthToken(GITHUB_TOKEN)
	return ghClient
}

func GetProjectReleaseByTag(project string, releaseTag string) (*github.RepositoryRelease, error) {
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

func GetProjectReleaseArtifacts(project string, releaseTag string) ([]*github.ReleaseAsset, error) {
	var assets []*github.ReleaseAsset

	release, err := GetProjectReleaseByTag(project, releaseTag)
	if err != nil {
		return nil, fmt.Errorf("could not get artifacts for release %s from github project %s: %w", releaseTag, project, err)
	}

	assets = append(assets, release.Assets...)

	return assets, nil
}

func GetProjectReleaseArtifactNames(project string, releaseTag string) ([]string, error) {
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
