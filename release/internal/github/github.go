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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/projectcalico/calico/release/internal/command"
)

const host = "github.com"

var baseURL = url.URL{Scheme: "https", Host: host}

var TokenEnvVars = []string{"GITHUB_TOKEN", "GH_TOKEN"}

// Authenticated reports whether a release can reach the GitHub API.
func Authenticated(r command.CommandRunner) bool {
	return resolveToken(r) != ""
}

type Repo struct {
	Org  string
	Name string
}

func (r Repo) Validate() error {
	var errs []error
	if r.Org == "" {
		errs = append(errs, fmt.Errorf("no github organization specified"))
	}
	if r.Name == "" {
		errs = append(errs, fmt.Errorf("no github repository specified"))
	}
	return errors.Join(errs...)
}

func (r Repo) String() string {
	return r.Org + "/" + r.Name
}

// URL is the repository's page, or a page under it.
func (r Repo) URL(path ...string) string {
	return baseURL.JoinPath(append([]string{r.Org, r.Name}, path...)...).String()
}

// DownloadURL is where a release's artifacts are downloaded from.
func (r Repo) DownloadURL(tag string, file ...string) string {
	return r.URL(append([]string{"releases", "download", tag}, file...)...)
}

func (r Repo) BlobURL(ref, path string) string {
	return r.URL("blob", ref, path)
}

// OpenPRsURL lists the open pull requests from a head branch.
func (r Repo) OpenPRsURL(head string) string {
	return r.URL("pulls") + "?q=" + url.QueryEscape("is:open head:"+head)
}

type authTransport struct {
	next   http.RoundTripper
	runner command.CommandRunner

	once  sync.Once
	token string
}

func (g *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only intercept requests destined for GitHub API endpoints
	if req.URL.Host == host || strings.HasSuffix(req.URL.Host, "."+host) {
		g.once.Do(func() { g.token = resolveToken(command.Runner(g.runner)) })
		token := g.token

		if token != "" {
			// Deep copy request to keep it safe for parallel execution
			req = req.Clone(req.Context())

			// Inject only the Authorization token
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		}
	}

	transport := g.next
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}

// resolveToken retrieves the GitHub authentication token from environment variables
// or the GitHub CLI tool. Returns an empty string if no token is found.
func resolveToken(r command.CommandRunner) string {
	// 1. Check common environment variables first
	for _, envVar := range TokenEnvVars {
		if token := os.Getenv(envVar); token != "" {
			return token
		}
	}

	// 2. Fall back to executing the GitHub CLI tool (`gh auth token`)
	out, err := r.Run("gh", []string{"auth", "token"})
	if err == nil {
		token := strings.TrimSpace(out)
		if token != "" {
			return token
		}
	}

	// Fallback to anonymous request if no credentials could be recovered
	return ""
}
