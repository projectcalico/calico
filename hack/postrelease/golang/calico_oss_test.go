package calico_oss_test

import (
	"calico_postrelease/pkg/container"
	"calico_postrelease/pkg/registry"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var release_tag = "v3.27.4"

var expected_arches = []string{"amd64", "arm64", "s390x", "ppc64le"}

var expected_images = []string{
	"calico/node",
	"calico/ctl",
	"calico/apiserver",
	"calico/typha",
	"calico/cni",
	"calico/kube-controllers",
	// "calico/upgrade",
	"calico/flannel-migration-controller",
	"calico/dikastes",
	// "calico/pilot-webhook",
	"calico/pod2daemon-flexvol",
	"calico/csi",
}

// Commenting these out because we don't currently tag the
// individual windows images. Should we?
// var expected_windows_tags = []string{
// 	"windows-ltsc2022",
// 	"windows-1809",
// }

var expected_windows_images = []string{
	"calico/cni-windows",
	"calico/node-windows",
}

func TestGolang(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Calico OSS Postrelease Test Suite")
}

var _ = Describe(
	"Validate Container Image Publishing",
	func() {
		var operatorImage container.Image
		var quayRegistry registry.QuayRegistry = registry.NewQuayRegistry()
		var gcrRegistries = []registry.GCRRegistry{
			registry.NewGCRRegistry("gcr.io"),
			registry.NewGCRRegistry("us.gcr.io"),
			registry.NewGCRRegistry("asia.gcr.io"),
			registry.NewGCRRegistry("us.gcr.io"),
		}
		var imagesToTest = make([]container.Image, 0)

		for _, image_name := range expected_images {
			for _, arch_name := range expected_arches {
				image_name := image_name
				arch_name := arch_name
				var containerImage = container.Image{
					Name: image_name,
					Tag:  fmt.Sprintf("%s-%s", release_tag, arch_name),
				}
				imagesToTest = append(imagesToTest, containerImage)
			}
		}

		for _, image_name := range expected_windows_images {
			var containerImage = container.Image{
				Name: image_name,
				Tag:  release_tag,
			}
			imagesToTest = append(imagesToTest, containerImage)
			// Comment this out because we don't tag windows-revision-specific
			// images when we publish a release (maybe we should?)
			//
			// 	for _, windows_tag := range expected_windows_tags {
			// 		image_name := image_name
			// 		windows_tag := windows_tag
			// 		var containerImage = container.Image{
			// 			Name: image_name,
			// 			Tag:  fmt.Sprintf("%s-%s", release_tag, windows_tag),
			// 		}
			// 		images_to_test = append(imagesToTest, containerImage)

			// 	}
		}

		BeforeEach(func() {
			operatorImage = container.Image{
				Name: "tigera/operator",
				Tag:  "v1.32.3",
			}

		})

		Describe("Checking Image Presence", func() {
			Context("The operator image", func() {
				It("should exist", func() {
					Expect(quayRegistry.CheckImageExists(operatorImage)).NotTo(HaveOccurred())
				})
			})

			// Context("The Quay.io repository", func() {
			// 	for _, containerImage := range imagesToTest {
			// 		// fmt.Println(containerImage)
			// 		var image_path = fmt.Sprintf("%s:%s", containerImage.Name, containerImage.Tag)
			// 		It(fmt.Sprintf("should contain %s", image_path), func() {
			// 			Expect(quayRegistry.CheckImageExists(containerImage)).NotTo(HaveOccurred())
			// 		})
			// 	}

			// })

			for _, gcrRegistry := range gcrRegistries {
				Context(fmt.Sprintf("The GCR Repository %s", gcrRegistry.HostName), func() {
					for _, containerImage := range imagesToTest {
						var image_path = fmt.Sprintf("%s:%s", containerImage.Name, containerImage.Tag)
						It(fmt.Sprintf("should contain %s", image_path), func() {
							Expect(gcrRegistry.CheckImageExists(containerImage)).NotTo(HaveOccurred())
						})
					}
				})
			}
		})
	})
