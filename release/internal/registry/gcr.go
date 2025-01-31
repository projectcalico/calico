// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
)

const GCRRegistry = "gcr.io"

func NewGCRRegistry(registry string) Registry {
	return &GCR{
		Region: strings.TrimSuffix(registry, "."+GCRRegistry),
	}
}

// GCR represents the Google Container Registry
type GCR struct {
	Region string
}

func (g *GCR) URL() string {
	if g.Region == "" {
		return GCRRegistry
	}
	return fmt.Sprintf("%s.%s", g.Region, GCRRegistry)
}

func (g *GCR) Token(img ImageRef) (string, error) {
	return command.Run("gcloud", []string{"auth", "print-access-token"})
}

func (g *GCR) TokenURL(scope string) string {
	return ""
}

func (g *GCR) ManifestURL(img ImageRef) string {
	return fmt.Sprintf("https://%s/v2/%s/manifests/%s", g.URL(), img.Repository(), img.Tag())
}
