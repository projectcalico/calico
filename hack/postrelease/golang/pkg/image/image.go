package image

import (
	"context"
	"fmt"
	"slices"

	"github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func platEqual(plat1 ocispec.Platform, plat2 ocispec.Platform) bool {
	if plat1.Architecture == plat2.Architecture &&
		plat1.OS == plat2.OS &&
		plat1.OSVersion == plat2.OSVersion &&
		plat1.Variant == plat2.Variant &&
		slices.Equal(plat1.OSFeatures, plat2.OSFeatures) {
		return true
	}
	return false
}

type Image struct {
	Hostname string
	Name     string
	Tag      string
}

func (img Image) NameWithTag() string {
	return fmt.Sprintf("%s:%s", img.Name, img.Tag)
}

func (img Image) GetURL() string {
	var img_url string
	if img.Hostname != "" {
		img_url = fmt.Sprintf("%s/%s:%s", img.Hostname, img.Name, img.Tag)
	} else {
		img_url = fmt.Sprintf("%s:%s", img.Name, img.Tag)
	}
	return img_url
}

func (img Image) GetManifest() {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	image_manifest, err := cli.DistributionInspect(context.Background(), img.GetURL(), "")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", image_manifest.Descriptor.Platform)

	for _, plat := range image_manifest.Platforms {
		fmt.Printf("%s %s %s %s %s\n", plat.Architecture, plat.OS, plat.OSVersion, plat.OSFeatures, plat.Variant)
	}
}
