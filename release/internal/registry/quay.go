package registry

import (
	"fmt"
)

// Quay represents the Quay registry
type Quay struct {
}

// URL returns the URL for the Quay registry
func (q *Quay) URL() string {
	return "quay.io"
}

// TokenURL returns the token URL for the Quay registry
func (q *Quay) TokenURL(repository string) string {
	return fmt.Sprintf("https://%s/v2/auth?scope=repository:%s:pull", q.URL(), repository)
}

// ManifestURL returns the manifest URL for the Quay registry
func (q *Quay) ManifestURL(img Image) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", q.URL(), img.Repository(), img.Tag())
}
