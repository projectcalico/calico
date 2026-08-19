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
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestCollectE2EBinaries(t *testing.T) {
	tests := []struct {
		name          string
		e2eBinaries   bool
		isHashRelease bool
		staged        []string
		want          []string
	}{
		{
			name:        "release flattens the staged binaries",
			e2eBinaries: true,
			staged:      []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test"},
			want:        []string{"e2e-linux-amd64.test", "e2e-linux-arm64.test"},
		},
		{
			name:        "unrelated staged files are left behind",
			e2eBinaries: true,
			staged:      []string{"e2e-linux-amd64.test", "notes.txt"},
			want:        []string{"e2e-linux-amd64.test"},
		},
		{
			name:          "hashrelease keeps only the files/e2e layout",
			e2eBinaries:   true,
			isHashRelease: true,
			staged:        []string{"e2e-linux-amd64.test"},
		},
		{
			name:        "disabled does nothing",
			e2eBinaries: false,
			staged:      []string{"e2e-linux-amd64.test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputDir := t.TempDir()
			e2eDir := filepath.Join(outputDir, "files", "e2e")
			require.NoError(t, os.MkdirAll(e2eDir, 0o755))
			for _, name := range tt.staged {
				require.NoError(t, os.WriteFile(filepath.Join(e2eDir, name), []byte(name), 0o755))
			}

			r := &CalicoManager{
				e2eBinaries:   tt.e2eBinaries,
				isHashRelease: tt.isHashRelease,
				outputDir:     outputDir,
			}
			require.NoError(t, r.collectE2EBinaries())

			entries, err := os.ReadDir(outputDir)
			require.NoError(t, err)
			var got []string
			for _, entry := range entries {
				if !entry.IsDir() {
					got = append(got, entry.Name())
				}
			}
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

// A missing files/e2e directory means the build never staged anything, which
// would otherwise ship a release with no e2e binaries and no warning.
func TestCollectE2EBinariesUnstagedErrors(t *testing.T) {
	r := &CalicoManager{e2eBinaries: true, outputDir: t.TempDir()}
	require.Error(t, r.collectE2EBinaries())
}
