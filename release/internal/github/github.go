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

const (
	Host    = "github.com"
	baseURL = "https://" + Host
)

// RepoURL is the repository a release is published from.
func RepoURL(org, repo string) (string, error) {
	return url.JoinPath(baseURL, org, repo)
}

// DownloadURL is where a release's artifacts are downloaded from.
func DownloadURL(org, repo, version string, file ...string) (string, error) {
	return joinRepo(org, repo, append([]string{"releases", "download", version}, file...)...)
}

// ReleaseURL is the release's page.
func ReleaseURL(org, repo, version string) (string, error) {
	return joinRepo(org, repo, "releases", "tag", version)
}

// OpenPullsURL lists the open pull requests from a branch.
func OpenPullsURL(org, repo, branch string) (string, error) {
	u, err := joinRepo(org, repo, "pulls")
	if err != nil {
		return "", err
	}
	return u + "?" + url.Values{"q": {"is:open head:" + branch}}.Encode(), nil
}

func joinRepo(org, repo string, parts ...string) (string, error) {
	base, err := RepoURL(org, repo)
	if err != nil {
		return "", err
	}
	return url.JoinPath(base, parts...)
}
