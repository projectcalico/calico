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

// Package github is how a release reaches GitHub.
package github

import "net/url"

const baseURL = "https://github.com"

var TokenEnvVars = []string{"GITHUB_TOKEN", "GH_TOKEN"}

// DownloadURL is where a release's artifacts are downloaded from.
func DownloadURL(org, repo, version string, file ...string) (string, error) {
	parts := append([]string{org, repo, "releases", "download", version}, file...)
	return url.JoinPath(baseURL, parts...)
}
