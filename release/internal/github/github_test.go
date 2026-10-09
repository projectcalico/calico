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

package github

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Pinned to literals: deriving them from the builders would pass for any URL.
func TestDownloadURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		file []string
		want string
	}{
		{"release", nil, "https://github.com/projectcalico/calico/releases/download/v3.30.0"},
		{"artifact", []string{"SHA256SUMS"}, "https://github.com/projectcalico/calico/releases/download/v3.30.0/SHA256SUMS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DownloadURL("projectcalico", "calico", "v3.30.0", tc.file...)
			if err != nil {
				t.Fatalf("building url: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveToken(t *testing.T) {
	// A fake gh, so the result does not depend on this machine's login.
	loggedIn := func(t *testing.T, token string) string {
		t.Helper()
		dir := t.TempDir()
		script := "#!/bin/sh\necho " + token + "\n"
		if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	for _, tc := range []struct {
		name string
		env  string
		cli  string
		want string
	}{
		{name: "the environment wins", env: "from-env", cli: "from-cli", want: "from-env"},
		{name: "the CLI when nothing is exported", cli: "from-cli", want: "from-cli"},
		{name: "no way in", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range TokenEnvVars {
				t.Setenv(key, "")
			}
			if tc.env != "" {
				t.Setenv(TokenEnvVars[0], tc.env)
			}
			if tc.cli != "" {
				t.Setenv("PATH", loggedIn(t, tc.cli))
			} else {
				t.Setenv("PATH", t.TempDir())
			}

			if got := resolveToken(); got != tc.want {
				t.Errorf("resolveToken() = %q, want %q", got, tc.want)
			}
			if got := Authenticated(); got != (tc.want != "") {
				t.Errorf("Authenticated() = %v, want %v", got, tc.want != "")
			}
		})
	}
}

func TestAuthTransport(t *testing.T) {
	t.Run("injects only for github", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			url      string
			wantAuth bool
		}{
			{name: "the API", url: "https://api.github.com/repos/o/r", wantAuth: true},
			{name: "asset uploads", url: "https://uploads.github.com/repos/o/r/releases/1/assets", wantAuth: true},
			{name: "the site itself", url: "https://github.com/o/r", wantAuth: true},
			{name: "a lookalike suffix", url: "https://notgithub.com/o/r", wantAuth: false},
			{name: "somewhere else entirely", url: "https://example.com/o/r", wantAuth: false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Setenv(TokenEnvVars[0], "tok")
				seen := &recordingTransport{}
				req, err := http.NewRequest(http.MethodGet, tc.url, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := (&GithubAuthTransport{Transport: seen}).RoundTrip(req); err != nil {
					t.Fatal(err)
				}
				if got := seen.auth != ""; got != tc.wantAuth {
					t.Errorf("Authorization sent = %v, want %v (header %q)", got, tc.wantAuth, seen.auth)
				}
				if req.Header.Get("Authorization") != "" {
					t.Error("the caller's request was mutated; it must be cloned")
				}
			})
		}
	})

	t.Run("drops the token on a redirect elsewhere", func(t *testing.T) {
		var got string
		elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Authorization")
		}))
		defer elsewhere.Close()
		gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/asset", http.StatusFound)
		}))
		defer gh.Close()

		t.Setenv(TokenEnvVars[0], "tok")
		req, err := http.NewRequest(http.MethodGet, gh.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&http.Client{Transport: &GithubAuthTransport{}}).Do(req); err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Errorf("the redirect target received %q, want no credential", got)
		}
	})
}

type recordingTransport struct{ auth string }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.auth = req.Header.Get("Authorization")
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}
