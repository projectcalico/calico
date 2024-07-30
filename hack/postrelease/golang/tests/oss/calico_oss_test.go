package oss

import (
	"calico_postrelease/pkg/container"
	"calico_postrelease/pkg/github"
	"calico_postrelease/pkg/helm"
	"calico_postrelease/pkg/openstack"
	"calico_postrelease/pkg/registry"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var calicoReleaseTag = os.Getenv("CALICO_VERSION")
var operatorReleaseVersion = os.Getenv("OPERATOR_VERSION")
var calicoProjectName = "projectcalico/calico"

var flannelProjectName = "coreos/flannel"
var flannelReleaseTag = os.Getenv("FLANNEL_VERSION")

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

func TestGolang(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Calico OSS Postrelease Test Suite")
}

var regCheck registry.RegistryChecker
var err error
var imagesToTest []container.Image

var _ = BeforeSuite(func() {
	regCheck, err = registry.New()
	if err != nil {
		fmt.Println("I guess something failed")
		panic(err)
	}
	imagesToTest = make([]container.Image, 400)

	imagesToTest = append(imagesToTest, container.Image{
		Name:     "operator",
		Tag:      operatorReleaseVersion,
		HostName: "quay.io",
	})
})

var _ = AfterSuite(func() {
	// if cacheHits, found := regCheck.Cache.Get("CacheHit"); found {
	// 	fmt.Printf("Cache hits: %v\n", cacheHits)
	// }
	// if cacheMiss, found := regCheck.Cache.Get("CacheMiss"); found {
	// 	fmt.Printf("Cache misses: %v\n", cacheMiss)
	// }
})

var _ = Describe(
	"Validate published image",
	Label("docker"),
	func() {
		for _, host_name := range dockerReleaseHosts {
			Context(
				fmt.Sprintf("at registry %s", host_name),
				Label(host_name),
				func() {

					for _, image_name := range expectedCalicoImages {
						Context(fmt.Sprintf("image %s", image_name), Label(image_name), func() {
							var containerImage = container.Image{
								Name:     image_name,
								Tag:      calicoReleaseTag,
								HostName: host_name,
							}
							It("should exist", func() {
								Expect(regCheck.CheckImageTagExists(containerImage)).NotTo(HaveOccurred())
							})
						})
					}
					for _, image_name := range expectedCalicoImages {
						Describe(fmt.Sprintf("image %s", image_name),
							Label("image_name"),
							func() {
								for _, arch_name := range expectedCalicoArches {
									image_name := image_name
									host_name := host_name
									arch_name := arch_name
									var containerImage = container.Image{
										Name:     image_name,
										Tag:      fmt.Sprintf("%s-%s", calicoReleaseTag, arch_name),
										HostName: host_name,
									}
									It(fmt.Sprintf("Should have %s", arch_name), Label(arch_name), func() {
										Expect(regCheck.CheckImageTagExists(containerImage)).NotTo(HaveOccurred())
									})
								}
							})
					}

					for _, image_name := range expectedWindowsImages {
						Context(fmt.Sprintf("arch-specific image %s", image_name), func() {
							var containerImage = container.Image{
								Name:     image_name,
								Tag:      calicoReleaseTag,
								HostName: host_name,
							}
							It("should exist", func() {
								Expect(regCheck.CheckImageTagExists(containerImage)).NotTo(HaveOccurred())
							})
						})

					}

				},
			)
		}

	})

var _ = Describe(
	"Validate calico release",
	Label("github"),
	Label("calico"),
	Ordered,
	func() {
		Context(fmt.Sprintf("release %s", calicoReleaseTag), func() {
			It("should be published", func() {
				_, err := github.GetProjectReleaseByTag(calicoProjectName, calicoReleaseTag)
				if err != nil {
					Fail(fmt.Sprintf("Error getting release tag %s from project %s", calicoReleaseTag, calicoProjectName))
				}
			})
			Context(
				"should contain asset",
				func() {
					releaseArtifactNames, err := github.GetProjectReleaseArtifactNames(calicoProjectName, calicoReleaseTag)
					if err != nil {
						Fail(fmt.Sprintf("Could not get release artifact names for %s: %s", calicoProjectName, err))
					}

					for _, desiredName := range expectedCalicoAssets {
						if strings.Contains(desiredName, "%s") {
							desiredName = fmt.Sprintf(desiredName, calicoReleaseTag)
						}
						It(desiredName, Label("asset"), func() {
							if !slices.Contains(releaseArtifactNames, desiredName) {
								Fail(fmt.Sprintf("missing asset %s in release", desiredName))
							}
						})
					}

				},
			)
		})
	})

var _ = Describe(
	"Validate flannel release",
	Label("github"),
	Label("flannel"),
	Ordered,
	func() {
		Context(fmt.Sprintf("release %s", calicoReleaseTag), func() {
			It("should be published", func() {
				_, err := github.GetProjectReleaseByTag(flannelProjectName, flannelReleaseTag)
				if err != nil {
					Fail(fmt.Sprintf("Error getting release tag %s from project %s", flannelReleaseTag, flannelProjectName))
				}
			})
			Context(
				"should contain asset",
				Ordered,
				func() {
					releaseArtifactNames, err := github.GetProjectReleaseArtifactNames(flannelProjectName, flannelReleaseTag)
					if err != nil {
						Fail(fmt.Sprintf("Could not get release artifact names for %s: %s", flannelProjectName, err))
					}

					for _, desiredName := range expectedFlannelAssets {
						if strings.Contains(desiredName, "%s") {
							desiredName = fmt.Sprintf(desiredName, flannelReleaseTag)
						}
						It(desiredName, Label("asset"), func() {
							if !slices.Contains(releaseArtifactNames, desiredName) {
								Fail(fmt.Sprintf("missing asset %s in release", desiredName))
							}
						})
					}

				},
			)
		})
	})

var _ = Describe(
	"Validate Openstack publishing",
	Label("openstack"),
	func() {
		var packageList = openstack.GetPackages(calicoReleaseTag)
		Context("check openstack files", func() {
			for _, packageObj := range packageList {
				It(
					fmt.Sprintf("should have published %s %s for %s", packageObj.Component, packageObj.Version, packageObj.OSVersion),
					Label(packageObj.Component),
					func() {
						resp, err := packageObj.Get()
						if err != nil {
							Fail("Failed to fetch package")
						}
						if resp.StatusCode != 200 {
							Fail(fmt.Sprintf("Caught unexpected HTTP status code %v", resp.StatusCode))
						}

					},
				)
			}
		})
	})

var _ = Describe(
	"Validate helm chart",
	Label("helm"),
	func() {
		Context("the latest helm chart", func() {
			It("should be in the published index", func() {
				index, err := helm.GetHelmIndex()
				if err != nil {
					Fail(fmt.Sprintf("could not fetch helm index: %s", err))
				}
				if !index.CheckVersionIsPublished(calicoReleaseTag) {
					Fail(fmt.Sprintf("helm index does not contain an entry for version %s", calicoReleaseTag))
				}
			})
			It("should be fetchable and load-able by helm", func() {
				err := helm.LoadHelmArchiveForVersion(calicoReleaseTag)
				if err != nil {
					Fail(fmt.Sprintf("%s", err))
				}
			})
		})
	})
