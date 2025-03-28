// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"fmt"
)

const QuayRegistry = "quay.io"

// Quay represents the Quay registry
type Quay struct{}

// URL returns the URL for the Quay registry
func (q *Quay) URL() string {
	return QuayRegistry
}

// Token returns the token to access the Docker registry for the image
func (q *Quay) Token(img ImageRef) (string, error) {
	var (
		token string
		err   error
		scope = fmt.Sprintf("repository:%s:pull", img.Repository())
	)
	if img.RequiresAuth() {
		token, err = getBearerTokenWithDefaultAuth(q, scope)
	} else {
		token, err = getBearerToken(q, scope)
	}
	return token, err
}

// TokenURL returns the token URL for the Quay registry
func (q *Quay) TokenURL(scope string) string {
	return fmt.Sprintf("https://%s/v2/auth?service=quay.io&scope=%s", q.URL(), scope)
}

// ManifestURL returns the manifest URL for the Quay registry
func (q *Quay) ManifestURL(img ImageRef) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", q.URL(), img.Repository(), img.Tag())
}
