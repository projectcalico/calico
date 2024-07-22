package registry

import (
	"fmt"
)

type Docker struct{}

func (d *Docker) URL() string {
	return "docker.io"
}

func (d *Docker) TokenURL(repository string) string {
	return "https://auth." + d.URL() + "/token?service=registry.docker.io&scope=repository:" + repository + ":pull"
}

func (d *Docker) ManifestURL(img Image) string {
	return fmt.Sprintf("https://registry-1.%s/v2/%s/manifests/%s", d.URL(), img.Repository(), img.Tag())
}
