package oss

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/hack/postrelease/golang/pkg/github"
)

var (
	calicoReleaseTag  = os.Getenv("CALICO_VERSION")
	calicoProjectName = "projectcalico/calico"
)

var expectedCalicoAssets = []string{
	"calico-windows-%s.zip",
	"calicoctl-darwin-amd64",
	"calicoctl-darwin-arm64",
	"calicoctl-linux-amd64",
	"calicoctl-linux-arm64",
	"calicoctl-linux-ppc64le",
	"calicoctl-linux-s390x",
	"calicoctl-windows-amd64.exe",
	"install-calico-windows.ps1",
	"metadata.yaml",
	"ocp.tgz",
	"release-%s.tgz",
	"SHA256SUMS",
	"tigera-operator-%s.tgz",
}

func TestMain(m *testing.M) {
	failed := false
	if calicoReleaseTag == "" {
		fmt.Println("Missing CALICO_VERSION variable!")
		failed = true
	}
	if failed {
		fmt.Println("Please set the appropriate variables and then re-run the test suite")
		os.Exit(2)
	}

	v := m.Run()
	os.Exit(v)
}

func Test_CalicoGithubRelease(t *testing.T) {
	_, err := github.GetProjectReleaseByTag(calicoProjectName, calicoReleaseTag)
	assert.NoError(t, err)

	releaseArtifactNames, err := github.GetProjectReleaseArtifactNames(calicoProjectName, calicoReleaseTag)
	assert.NoError(t, err)

	for _, desiredName := range expectedCalicoAssets {
		if strings.Contains(desiredName, "%s") {
			desiredName = fmt.Sprintf(desiredName, calicoReleaseTag)
		}
		testName := fmt.Sprintf("ReleaseAssetExists:%s", desiredName)
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			assert.Contains(t, releaseArtifactNames, desiredName)
		})
	}
}
