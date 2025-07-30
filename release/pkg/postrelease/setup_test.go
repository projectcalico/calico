package postrelease

import (
	"flag"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/utils"
)

var (
	linuxArches  = []string{"amd64", "arm64", "s390x", "ppc64le"}
	darwinArches = []string{"amd64", "arm64"}
)

var (
	releaseVersion, operatorVersion, flannelVersion  string
	githubOrg, githubRepo, githubRemote, githubToken string
	images                                           string
)

func init() {
	flag.StringVar(&releaseVersion, "release-version", "", "Version for the release")
	flag.StringVar(&operatorVersion, "operator-version", "", "Version for Tigera operator")
	flag.StringVar(&flannelVersion, "flannel-version", "", "Version for flannel")
	flag.StringVar(&githubOrg, "github-org", utils.ProjectCalicoOrg, "GitHub organization")
	flag.StringVar(&githubRepo, "github-repo", utils.CalicoRepoName, "GitHub repository")
	flag.StringVar(&githubRemote, "github-repo-remote", utils.DefaultRemote, "GitHub repository remote")
	flag.StringVar(&images, "images", "", "List of images to check")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token")
}

func checkVersion(t testing.TB, version string) {
	t.Helper()
	if version == "" {
		t.Fatal("No version provided")
	}
}

func checkImages(t testing.TB, images string) {
	t.Helper()
	if images == "" {
		t.Fatal("No images provided")
	}
	list := strings.Split(images, " ")
	if len(list) == 0 {
		t.Fatal("No images provided")
	}
}
