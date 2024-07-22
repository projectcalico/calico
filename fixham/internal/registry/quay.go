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
	return q.URL() + "/oauth/token?service=quay.io&scope=repository:" + repository + ":pull"
}

func (q *Quay) ManifestURL(img Image) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", q.URL(), img.Repository(), img.Tag())
}
