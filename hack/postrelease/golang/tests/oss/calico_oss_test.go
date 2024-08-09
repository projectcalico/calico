package oss

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"calico_postrelease/pkg/container"
	"calico_postrelease/pkg/github"
	"calico_postrelease/pkg/helm"
	"calico_postrelease/pkg/openstack"
	"calico_postrelease/pkg/registry"

	"github.com/stretchr/testify/assert"
)

var (
	calicoReleaseTag       = os.Getenv("CALICO_VERSION")
	operatorReleaseVersion = os.Getenv("OPERATOR_VERSION")
	calicoProjectName      = "projectcalico/calico"
)

var (
	flannelProjectName = "coreos/flannel"
	flannelReleaseTag  = os.Getenv("FLANNEL_VERSION")
)

var dockerReleaseHosts = []string{
	"docker.io",
	"quay.io",
	"gcr.io",
	"us.gcr.io",
	"asia.gcr.io",
	"eu.gcr.io",
}

var expectedCalicoArches = []string{"amd64", "arm64", "s390x", "ppc64le"}

var expectedCalicoImages = []string{
	"node",
	"ctl",
	"apiserver",
	"typha",
	"cni",
	"kube-controllers",
	// "upgrade",
	"flannel-migration-controller",
	"dikastes",
	// "pilot-webhook",
	"pod2daemon-flexvol",
	"csi",
}

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

// Commenting these out because we don't currently tag the
// individual windows images. Should we?
// var expected_windows_tags = []string{
// 	"windows-ltsc2022",
// 	"windows-1809",
// }

var expectedWindowsImages = []string{
	"cni-windows",
	"node-windows",
}

var (
	regCheck     registry.Checker
	err          error
	imagesToTest []container.Image
)

func TestMain(m *testing.M) {
	var failed = false
	if calicoReleaseTag == "" {
		fmt.Println("Missing CALICO_RELEASE variable!")
		failed = true
	}
	if operatorReleaseVersion == "" {
		fmt.Println("Missing OPERATOR_RELEASE variable!")
		failed = true
	}
	if flannelReleaseTag == "" {
		fmt.Println("Missing FLANNEL_RELEASE variable!")
		failed = true
	}
	if failed {
		fmt.Println("Please set the appropriate variables and then re-run the test suite")
		os.Exit(2)
	}

	v := m.Run()
	if v == 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func Test_ImagesPublished(t *testing.T) {
	t.Parallel()
	regCheck, err = registry.New()
	if err != nil {
		fmt.Println("I guess something failed")
		panic(err)
	}
	imagesToTest = make([]container.Image, 0)

	containerImage := container.Image{
		Name:     "tigera/operator",
		Tag:      operatorReleaseVersion,
		HostName: "quay.io",
	}

	imagesToTest = append(imagesToTest, containerImage)
	fmt.Println(containerImage.FullPath())
	for _, hostName := range dockerReleaseHosts {
		for _, imageName := range expectedCalicoImages {

			containerImage := container.Image{
				Name:     imageName,
				Tag:      calicoReleaseTag,
				HostName: hostName,
			}

			imagesToTest = append(imagesToTest, containerImage)

			for _, archName := range expectedCalicoArches {
				containerImage := container.Image{
					Name:     imageName,
					Tag:      fmt.Sprintf("%s-%s", calicoReleaseTag, archName),
					HostName: hostName,
				}
				imagesToTest = append(imagesToTest, containerImage)
			}
		}
		for _, imageName := range expectedWindowsImages {

			containerImage := container.Image{
				Name:     imageName,
				Tag:      calicoReleaseTag,
				HostName: hostName,
			}

			imagesToTest = append(imagesToTest, containerImage)
		}
	}
	for _, ci := range imagesToTest {
		testName := fmt.Sprintf("ImageVerification:%s", ci.FullPathWithTag())
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			err := regCheck.CheckImageTagExists(ci)
			assert.NoError(t, err)
		})
	}

	t.Cleanup(func() {
		var hitsCount int
		var missesCount int
		hits, _ := regCheck.Cache.Get("CacheHit")
		misses, _ := regCheck.Cache.Get("CacheMiss")
		hitsCount = hits.(int)
		missesCount = misses.(int)
		fmt.Printf("Got %v cache hits, %v misses (%v%% hit rate)\n", hitsCount, missesCount, hitsCount/(hitsCount+missesCount)*100)
	})

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

func Test_OpenStackPublished(t *testing.T) {
	packageList := openstack.GetPackages(calicoReleaseTag)
	for packagePlatform, packageObjList := range packageList {
		t.Run(packagePlatform, func(t *testing.T) {
			for _, packageObj := range packageObjList {
				testName := fmt.Sprintf("%s/%s/%s:%s", packageObj.OSVersion, packageObj.Arch, packageObj.Component, packageObj.Version)
				fmt.Println(packageObj)
				t.Run(testName, func(t *testing.T) {
					t.Parallel()
					resp, err := packageObj.Head()
					assert.NoError(t, err)
					assert.Equal(t, 200, resp.StatusCode, "blahblah")
				})
			}
		})
	}

}

func Test_ValidateHelmChart(t *testing.T) {
	t.Parallel()
	t.Run("HelmChartIsInIndex", func(t *testing.T) {
		t.Parallel()
		index, err := helm.GetIndex()
		assert.NoError(t, err)
		assert.True(t, index.CheckVersionIsPublished(calicoReleaseTag))
	})

	t.Run("HelmChartCanBeLoaded", func(t *testing.T) {
		t.Parallel()
		err := helm.LoadArchiveForVersion(calicoReleaseTag)
		assert.NoError(t, err)
	})

}
