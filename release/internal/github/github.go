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

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/projectcalico/calico/release/internal/command"
)

const baseURL = "https://github.com"

var TokenEnvVars = []string{"GITHUB_TOKEN", "GH_TOKEN"}

// Authenticated reports whether a release can reach the GitHub API.
func Authenticated() bool {
	return resolveToken() != ""
}

// DownloadURL is where a release's artifacts are downloaded from.
func DownloadURL(org, repo, version string, file ...string) (string, error) {
	parts := append([]string{org, repo, "releases", "download", version}, file...)
	return url.JoinPath(baseURL, parts...)
}

type GithubAuthTransport struct {
	Transport http.RoundTripper

	once  sync.Once
	token string
}

func (g *GithubAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only intercept requests destined for GitHub API endpoints
	if req.URL.Host == "github.com" || strings.HasSuffix(req.URL.Host, ".github.com") {
		g.once.Do(func() { g.token = resolveToken() })
		token := g.token

		if token != "" {
			// Deep copy request to keep it safe for parallel execution
			req = req.Clone(req.Context())

			// Inject only the Authorization token
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		}
	}

	transport := g.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}

// resolveToken retrieves the GitHub authentication token from environment variables
// or the GitHub CLI tool. Returns an empty string if no token is found.
func resolveToken() string {
	// 1. Check common environment variables first
	for _, envVar := range TokenEnvVars {
		if token := os.Getenv(envVar); token != "" {
			return token
		}
	}

	// 2. Fall back to executing the GitHub CLI tool (`gh auth token`)
	out, err := command.Run("gh", []string{"auth", "token"})
	if err == nil {
		token := strings.TrimSpace(out)
		if token != "" {
			return token
		}
	}

	// Fallback to anonymous request if no credentials could be recovered
	return ""
}
