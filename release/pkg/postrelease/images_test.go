package postrelease

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var excludeImageArch = map[string][]string{
	"calico/envoy-proxy": {"ppc64le", "s390x"},
	"calico/whisker":     {"ppc64le", "s390x"},
}

func TestImagesPublished(t *testing.T) {
	t.Run("Calico", func(t *testing.T) {
		t.Parallel()

		checkVersion(t, releaseVersion)
		checkImages(t, images)

		for _, reg := range registry.DefaultCalicoRegistries {
			for _, image := range strings.Split(images, " ") {
				if strings.Contains(image, operator.DefaultImage) {
					// Operator images are checked separately
					continue
				}
				fqImage := fmt.Sprintf("%s/%s:%s", reg, image, releaseVersion)
				t.Run(fqImage, func(t *testing.T) {
					if ok, err := registry.CheckImage(fqImage); err != nil {
						t.Fatalf("failed to check image %s: %v", fqImage, err)
					} else if !ok {
						t.Fatalf("image (%s) not found", fqImage)
					}
					if !strings.HasSuffix(image, "windows") {
						for _, arch := range linuxArches {
							if excludeArchs, ok := excludeImageArch[image]; ok && slices.Contains(excludeArchs, arch) {
								continue
							}
							t.Run(fmt.Sprintf("linux %s", arch), func(t *testing.T) {
								fqArchImage := fmt.Sprintf("%s-%s", fqImage, arch)
								if ok, err := registry.CheckImage(fqArchImage); err != nil {
									t.Fatalf("failed to check image %s: %v", fqArchImage, err)
								} else if !ok {
									t.Fatalf("image (%s) not found", fqArchImage)
								}
							})
						}
					}
				})
			}
		}
	})

	t.Run("Tigera Operator", func(t *testing.T) {
		t.Parallel()

		checkVersion(t, operatorVersion)

		fqOperatorImage := fmt.Sprintf("%s/%s:%s", operator.DefaultRegistry, operator.DefaultImage, operatorVersion)
		if ok, err := registry.CheckImage(fqOperatorImage); err != nil {
			t.Fatalf("failed to check image %s: %v", fqOperatorImage, err)
		} else if !ok {
			t.Fatalf("image (%s) not found", fqOperatorImage)
		}

		for _, arch := range linuxArches {
			t.Run(fmt.Sprintf("linux %s", arch), func(t *testing.T) {
				fqImage := fmt.Sprintf("%s-%s", fqOperatorImage, arch)
				if ok, err := registry.CheckImage(fqImage); err != nil {
					t.Fatalf("failed to check image %s: %v", fqImage, err)
				} else if !ok {
					t.Fatalf("image (%s) not found", fqImage)
				}
			})
		}
	})

	t.Run("Flannel", func(t *testing.T) {
		t.Parallel()

		checkVersion(t, flannelVersion)

		fqImage := fmt.Sprintf("quay.io/coreos/flannel:%s", flannelVersion)
		if ok, err := registry.CheckImage(fqImage); err != nil {
			t.Fatalf("failed to check image %s: %v", fqImage, err)
		} else if !ok {
			t.Fatalf("image (%s) not found", fqImage)
		}
	})
}

func TestImagesInMetadata(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)
	checkImages(t, images)

	var expectedImages []string
	addOperator := true
	for _, image := range strings.Split(images, " ") {
		if strings.Contains(image, operator.DefaultImage) {
			addOperator = false
			expectedImages = append(expectedImages, fmt.Sprintf("%s/%s:%s", operator.DefaultRegistry, operator.DefaultImage, operatorVersion))
		}
		expectedImages = append(expectedImages, fmt.Sprintf("%s:%s", image, releaseVersion))
	}
	if len(expectedImages) == 0 {
		t.Fatal("no images provided")
	}
	if addOperator {
		expectedImages = append(expectedImages, fmt.Sprintf("%s/%s:%s", operator.DefaultRegistry, operator.DefaultImage, operatorVersion))
	}
	t.Logf("expected images: %v", expectedImages)

	metadataImages, err := getMetadataImages()
	if err != nil {
		t.Fatalf("failed to get %s metadata images: %v", releaseVersion, err)
	}
	t.Logf("metadata images: %v", metadataImages)

	if len(metadataImages) != len(expectedImages) {
		t.Errorf("expected %d images in metadata, got %d", len(expectedImages), len(metadataImages))
	}
	var diff []string
	for _, expectedImage := range expectedImages {
		if !slices.Contains(metadataImages, expectedImage) {
			diff = append(diff, expectedImage)
		}
	}
	if len(diff) > 0 {
		t.Fatalf("images in metadata missing the following: %v", diff)
	}
}

func getMetadataImages() ([]string, error) {
	metadataURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s", githubOrg, githubRepo, releaseVersion, metadataFileName)

	// Fetch the metadata
	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata from %s: %v", metadataURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch metadata: %v", resp.Status)
	}

	var metadata struct {
		Images []string `yaml:"images"`
	}
	if err := yaml.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %v", err)
	}

	return metadata.Images, nil
}
