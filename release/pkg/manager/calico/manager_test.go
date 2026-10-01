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

package calico

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeRunner is a command.CommandRunner that records every invocation so tests
// can assert what was run.
type fakeRunner struct {
	// calls records every command invoked, as "name arg1 arg2 ...".
	calls []string

	// envs records the env passed alongside each recorded call, by index.
	envs [][]string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{}
}

func (f *fakeRunner) record(name string, args, env []string) (string, error) {
	f.calls = append(f.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	f.envs = append(f.envs, env)
	return "", nil
}

func (f *fakeRunner) Run(name string, args, env []string) (string, error) {
	return f.record(name, args, env)
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	_, err := f.record(name, args, env)
	return err
}

func (f *fakeRunner) RunInDir(dir, name string, args, env []string) (string, error) {
	return f.record(name, args, env)
}

func (f *fakeRunner) RunInDirNoCapture(dir, name string, args, env []string) error {
	_, err := f.record(name, args, env)
	return err
}

// envFor returns the env of the first recorded call matching the given prefix.
func (f *fakeRunner) envFor(prefix string) []string {
	for i, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return f.envs[i]
		}
	}
	return nil
}

func TestOwnerFromRemoteURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{
			name: "SSH with .git suffix",
			url:  "git@github.com:projectcalico/calico.git",
			want: "projectcalico",
		},
		{
			name: "SSH without .git suffix",
			url:  "git@github.com:projectcalico/calico",
			want: "projectcalico",
		},
		{
			name: "HTTPS with .git suffix",
			url:  "https://github.com/projectcalico/calico.git",
			want: "projectcalico",
		},
		{
			name: "HTTPS without .git suffix",
			url:  "https://github.com/projectcalico/calico",
			want: "projectcalico",
		},
		{
			name: "SSH fork",
			url:  "git@github.com:myFork/calico.git",
			want: "myFork",
		},
		{
			name: "HTTPS fork",
			url:  "https://github.com/myFork/calico.git",
			want: "myFork",
		},
		{
			name: "SSH with nested path",
			url:  "git@github.com:org/sub/repo.git",
			want: "sub",
		},
		{
			name:    "bare hostname no path",
			url:     "github.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			url:     "",
			wantErr: true,
		},
		{
			name:    "local path",
			url:     "/tmp/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ownerFromRemoteURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ownerFromRemoteURL(%q) = %q, want error", tt.url, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ownerFromRemoteURL(%q) error = %v", tt.url, err)
				return
			}
			if got != tt.want {
				t.Errorf("ownerFromRemoteURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

// TestE2EArchitectures covers the supported-arch intersection: an empty set
// means "all" (the tooling-wide convention), the four-arch default drops
// ppc64le/s390x, a narrowed build keeps only its supported arches, and an
// unsupported-only set yields none.
func TestE2EArchitectures(t *testing.T) {
	tests := []struct {
		name       string
		configured []string
		want       []string
	}{
		{"empty means all supported", nil, []string{"amd64", "arm64"}},
		{"default four arches drop ppc64le/s390x", []string{"amd64", "arm64", "ppc64le", "s390x"}, []string{"amd64", "arm64"}},
		{"narrowed build keeps only its supported arch", []string{"arm64"}, []string{"arm64"}},
		{"unsupported-only yields none", []string{"ppc64le", "s390x"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e2eArchitectures(tt.configured); !slices.Equal(got, tt.want) {
				t.Errorf("e2eArchitectures(%v) = %v, want %v", tt.configured, got, tt.want)
			}
		})
	}
}

// TestBuildE2EBinariesUsesARCHES asserts the e2e build is restricted through
// ARCHES, not VALIDARCHES (lib.Makefile assigns VALIDARCHES with `=`, so passing
// it via the environment is a no-op).
func TestBuildE2EBinariesUsesARCHES(t *testing.T) {
	repoRoot := t.TempDir()
	// Stage a built e2e binary so the post-build hard-link step succeeds.
	e2eBinDir := filepath.Join(repoRoot, "e2e", "bin", "k8s")
	if err := os.MkdirAll(e2eBinDir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e2eBinDir, "e2e-linux-amd64.test"), []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	f := newFakeRunner()
	r := &CalicoManager{
		runner:        f,
		repoRoot:      repoRoot,
		outputDir:     t.TempDir(),
		calicoVersion: "v3.32.0-0.dev-1-gabcdef123456",
	}

	if err := r.buildE2EBinaries([]string{"amd64", "arm64"}); err != nil {
		t.Fatalf("buildE2EBinaries() unexpected error: %v", err)
	}

	makePrefix := "make -C " + filepath.Join(repoRoot, "e2e") + " build-all"
	env := f.envFor(makePrefix)
	if env == nil {
		t.Fatalf("e2e build-all was not run (calls: %v)", f.calls)
	}
	// Only inspect the arch env vars: env also carries os.Environ(), which can
	// hold secrets that must not be printed on failure.
	var archEnv []string
	for _, e := range env {
		if strings.HasPrefix(e, "ARCHES=") || strings.HasPrefix(e, "VALIDARCHES=") {
			archEnv = append(archEnv, e)
		}
	}
	if !slices.Contains(archEnv, "ARCHES=amd64 arm64") {
		t.Errorf("e2e build-all arch env = %v, want ARCHES=amd64 arm64", archEnv)
	}
	for _, e := range archEnv {
		if strings.HasPrefix(e, "VALIDARCHES=") {
			t.Errorf("e2e build-all should not set VALIDARCHES (lib.Makefile ignores it): %s", e)
		}
	}
}
