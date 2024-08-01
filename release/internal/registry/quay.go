package registry

import (
	"fmt"
)

// Quay represents the Quay registry
type Quay struct{}

// URL returns the URL for the Quay registry
func (q *Quay) URL() string {
	return "quay.io"
}

// TokenURL returns the token URL for the Quay registry
func (q *Quay) TokenURL(scope string) string {
	return fmt.Sprintf("https://%s/v2/auth?service=quay.io&scope=%s", q.URL(), scope)
}

// ManifestURL returns the manifest URL for the Quay registry
func (q *Quay) ManifestURL(img ImageRef) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", q.URL(), img.Repository(), img.Tag())
}
