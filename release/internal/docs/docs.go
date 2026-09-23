// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package docs

import (
	"net/url"
	"strings"

	"github.com/projectcalico/calico/release/internal/version"
)

const BaseURL = "https://docs.tigera.io"

var (
	BaseArtifactsURL = "https://raw.githubusercontent.com/projectcalico/calico"
	ProductSlug      = "calico"
)

type Site struct {
	Version version.Version
}

func (d Site) URL() (string, error) {
	stream := strings.TrimPrefix(d.Version.PrimaryStream(), "v")
	return url.JoinPath(BaseURL, ProductSlug, stream)
}

func (d Site) DownloadsURL() (string, error) {
	return url.JoinPath(BaseArtifactsURL, d.Version.FormattedString())
}
