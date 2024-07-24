package registry

import (
	"fmt"
)

type Docker struct{}

func (d *Docker) URL() string {
	return "docker.io"
}

func (d *Docker) TokenURL(repository string) string {
	return fmt.Sprintf("https://auth.%s/token?service=registry.docker.io&scope=repository:%s:pull", d.URL(), repository)
}

func (d *Docker) ManifestURL(img Image) string {
	return fmt.Sprintf("https://registry-1.%s/v2/%s/manifests/%s", d.URL(), img.Repository(), img.Tag())
}
