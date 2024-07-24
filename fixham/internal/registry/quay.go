package registry

import (
	"fmt"
)

type Quay struct {
}

func (q *Quay) URL() string {
	return "quay.io"
}

func (q *Quay) TokenURL(repository string) string {
	return fmt.Sprintf("https://quay.io/v2/auth?scope=repository:%s:pull", repository)
}

func (q *Quay) ManifestURL(img Image) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", q.URL(), img.Repository(), img.Tag())
}
