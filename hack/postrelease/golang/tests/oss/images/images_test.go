package oss

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/hack/postrelease/golang/pkg/container"
	"github.com/projectcalico/calico/hack/postrelease/golang/pkg/registry"
)

var (
	calicoReleaseTag       = os.Getenv("CALICO_VERSION")
	operatorReleaseVersion = os.Getenv("OPERATOR_VERSION")
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
	"key-cert-provisioner",
}

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
	failed := false
	if calicoReleaseTag == "" {
		fmt.Println("Missing CALICO_VERSION variable!")
		failed = true
	}
	if operatorReleaseVersion == "" {
		fmt.Println("Missing OPERATOR_RELEASE variable!")
		failed = true
	}
	if failed {
		fmt.Println("Please set the appropriate variables and then re-run the test suite")
		os.Exit(2)
	}

	v := m.Run()
	os.Exit(v)
}

func Test_ImagesPublished(t *testing.T) {
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
