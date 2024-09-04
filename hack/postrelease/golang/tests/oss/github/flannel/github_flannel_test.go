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
	flannelProjectName = "coreos/flannel"
	flannelReleaseTag  = os.Getenv("FLANNEL_VERSION")
)

var expectedFlannelAssets = []string{
	"flannel-%s-linux-amd64.tar.gz",
	"flannel-%s-linux-arm.tar.gz",
	"flannel-%s-linux-arm64.tar.gz",
	"flannel-%s-linux-mips64le.tar.gz",
	"flannel-%s-linux-ppc64le.tar.gz",
	"flannel-%s-linux-s390x.tar.gz",
	"flannel-%s-windows-amd64.tar.gz",
	"flannel.tgz",
	"flanneld-amd64",
	"flanneld-arm",
	"flanneld-arm64",
	"flanneld-mips64le",
	"flanneld-ppc64le",
	"flanneld-s390x",
	"flanneld-%s-amd64.docker",
	"flanneld-%s-arm.docker",
	"flanneld-%s-arm64.docker",
	"flanneld-%s-mips64le.docker",
	"flanneld-%s-ppc64le.docker",
	"flanneld-%s-s390x.docker",
	"flanneld.exe",
	"kube-flannel-psp.yml",
	"kube-flannel.yml",
}

func TestMain(m *testing.M) {
	failed := false
	if flannelReleaseTag == "" {
		fmt.Println("Missing FLANNEL_RELEASE variable!")
		failed = true
	}
	if failed {
		fmt.Println("Please set the appropriate variables and then re-run the test suite")
		os.Exit(2)
	}

	v := m.Run()
	os.Exit(v)
}

func Test_FlannelGithubRelease(t *testing.T) {
	_, err := github.GetProjectReleaseByTag(flannelProjectName, flannelReleaseTag)
	assert.NoError(t, err)

	releaseArtifactNames, err := github.GetProjectReleaseArtifactNames(flannelProjectName, flannelReleaseTag)
	assert.NoError(t, err)

	for _, desiredName := range expectedFlannelAssets {
		if strings.Contains(desiredName, "%s") {
			desiredName = fmt.Sprintf(desiredName, flannelReleaseTag)
		}
		testName := fmt.Sprintf("ReleaseAssetExists:%s", desiredName)
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			assert.Contains(t, releaseArtifactNames, desiredName)
		})
	}
}
