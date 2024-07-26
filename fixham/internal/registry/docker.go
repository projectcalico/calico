package registry

import (
	"fmt"
)

// Docker represents the Docker registry
type Docker struct{}

// URL returns the URL for the Docker registry
func (d *Docker) URL() string {
	return "docker.io"
}

// TokenURL returns the token URL for the Docker registry
func (d *Docker) TokenURL(repository string) string {
	return fmt.Sprintf("https://auth.%s/token?service=registry.docker.io&scope=repository:%s:pull", d.URL(), repository)
}

// ManifestURL returns the manifest URL for the Docker registry
func (d *Docker) ManifestURL(img Image) string {
	return fmt.Sprintf("https://registry-1.%s/v2/%s/manifests/%s", d.URL(), img.Repository(), img.Tag())
}
