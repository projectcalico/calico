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

const DockerRegistry = "docker.io"

// Docker represents the Docker registry
type Docker struct{}

// URL returns the URL for the Docker registry
func (d *Docker) URL() string {
	return DockerRegistry
}

// Token returns the token to access the Docker registry for the image
func (d *Docker) Token(img ImageRef) (string, error) {
	var (
		token string
		err   error
		scope = fmt.Sprintf("repository:%s:pull", img.Repository())
	)
	if img.RequiresAuth() {
		token, err = getBearerTokenWithDefaultAuth(d, scope)
	} else {
		token, err = getBearerToken(d, scope)
	}
	return token, err
}

// TokenURL returns the token URL for the Docker registry
func (d *Docker) TokenURL(scope string) string {
	return fmt.Sprintf("https://auth.%s/token?service=registry.docker.io&scope=%s", d.URL(), scope)
}

// ManifestURL returns the manifest URL for the Docker registry
func (d *Docker) ManifestURL(img ImageRef) string {
	return fmt.Sprintf("https://registry-1.%s/v2/%s/manifests/%s", d.URL(), img.Repository(), img.Tag())
}
