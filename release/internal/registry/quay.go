package registry

import (
	"fmt"
	"strings"
)

// Quay represents the Quay registry
type Quay struct{}

// URL returns the URL for the Quay registry
func (q *Quay) URL() string {
	return "quay.io"
}

// TokenURL returns the token URL for the Quay registry
func (q *Quay) TokenURL(scope string) string {
	return fmt.Sprintf("https://%s/v2/auth?scope=%s", q.URL(), scope)
}

// AuthTokenURL returns the token URL for the Docker registry
func (d *Quay) AuthTokenURL(auth, scope string) string {
	parts := strings.Split(auth, ":")
	return fmt.Sprintf("https://%s/v2/auth?user=%s&password=%s&scope=%s",
		d.URL(), parts[0], parts[1], scope)
}

// ManifestURL returns the manifest URL for the Quay registry
func (q *Quay) ManifestURL(img Image) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", q.URL(), img.Repository(), img.Tag())
}
