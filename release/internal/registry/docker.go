package registry

import (
	"fmt"
	"strings"
)

// Docker represents the Docker registry
type Docker struct{}

// URL returns the URL for the Docker registry
func (d *Docker) URL() string {
	return "docker.io"
}

// TokenURL returns the token URL for the Docker registry
func (d *Docker) TokenURL(scope string) string {
	return fmt.Sprintf("https://auth.%s/token?service=registry.docker.io&scope=%s", d.URL(), scope)
}

// AuthTokenURL returns the token URL for the Docker registry
func (d *Docker) AuthTokenURL(auth, scope string) string {
	parts := strings.Split(auth, ":")
	return fmt.Sprintf("https://auth.%s/token?service=registry.docker.io&user=%s&password=%s&scope=%s",
		d.URL(), parts[0], parts[1], scope)
}

// ManifestURL returns the manifest URL for the Docker registry
func (d *Docker) ManifestURL(img Image) string {
	return fmt.Sprintf("https://registry-1.%s/v2/%s/manifests/%s", d.URL(), img.Repository(), img.Tag())
}
