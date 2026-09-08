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

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const imageInspectOutput = `[
  {
    "Id": "sha256:0123",
    "Created": "2026-01-02T03:04:05.678901234Z",
    "RepoTags": ["quay.io/tigera/operator:v1.42.6"],
    "RepoDigests": [
      "some.other.registry/tigera/operator@sha256:aaa",
      "quay.io/tigera/operator@sha256:bbb"
    ]
  }
]`

const manifestInspectOutput = `{
  "manifests": [
    {"platform": {"architecture": "amd64", "os": "linux"}},
    {"platform": {"architecture": "arm64", "os": "linux"}}
  ]
}`

// TestParseImageInspect also covers that the inspection can be handed over
// base64-encoded, as a caller passing it through the environment does.
func TestParseImageInspect(t *testing.T) {
	t.Parallel()

	for _, content := range []string{imageInspectOutput, encode(imageInspectOutput)} {
		img, err := parseImageInspect(content, "quay.io/tigera/operator")
		if err != nil {
			t.Fatalf("parseImageInspect: %v", err)
		}
		if want := "quay.io/tigera/operator@sha256:bbb"; img.digest != want {
			t.Errorf("digest is %q, want %q", img.digest, want)
		}
		if want := "2026-01-02T03:04:05.678901234Z"; img.created != want {
			t.Errorf("created is %q, want %q", img.created, want)
		}
	}
}

func TestParseImageInspectErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
	}{
		{name: "neither JSON nor base64", content: "not base64!"},
		{name: "not JSON", content: "{"},
		{name: "empty output", content: "[]"},
		{
			name:    "no operator digest",
			content: `[{"Created": "2026-01-02T03:04:05Z", "RepoDigests": ["docker.io/library/busybox@sha256:aaa"]}]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseImageInspect(tc.content, "quay.io/tigera/operator"); err == nil {
				t.Error("parseImageInspect succeeded, want an error")
			}
		})
	}
}

func TestParseArchitectures(t *testing.T) {
	t.Parallel()

	for _, content := range []string{manifestInspectOutput, encode(manifestInspectOutput)} {
		architectures, err := parseArchitectures(content)
		if err != nil {
			t.Fatalf("parseArchitectures: %v", err)
		}
		if got := strings.Join(architectures, ","); got != "amd64,arm64" {
			t.Errorf("architectures are %q, want \"amd64,arm64\"", got)
		}
	}

	if _, err := parseArchitectures(`{"manifests": []}`); err == nil {
		t.Error("parseArchitectures of an empty manifest list succeeded, want an error")
	}
}

// TestInspectImageOverrides checks that passing both inspections in keeps docker
// out of it, which is what lets this run with no registry to reach.
func TestInspectImageOverrides(t *testing.T) {
	t.Parallel()

	img, err := inspectImage(t.Context(), "quay.io/tigera/operator", "quay.io/tigera/operator:v1.42.6",
		imageInspectOutput, manifestInspectOutput)
	if err != nil {
		t.Fatalf("inspectImage: %v", err)
	}
	if want := "quay.io/tigera/operator@sha256:bbb"; img.digest != want {
		t.Errorf("digest is %q, want %q", img.digest, want)
	}
	if got := strings.Join(img.architectures, ","); got != "amd64,arm64" {
		t.Errorf("architectures are %q, want \"amd64,arm64\"", got)
	}
}

func TestReleaseStream(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"1.42.6": "1.42",
		"1.42":   "1",
		"1":      "1",
	}
	for version, want := range cases {
		if got := releaseStream(version); got != want {
			t.Errorf("releaseStream(%q) is %q, want %q", version, got, want)
		}
	}
}

func TestUpdateDockerfile(t *testing.T) {
	// updateDockerfile works on paths relative to the operator directory, so
	// this test cannot run in parallel with the rest.
	t.Chdir(t.TempDir())
	writeFile(t, bundleDockerfile, `FROM scratch

# Core bundle labels.
LABEL operators.operatorframework.io.bundle.package.v1=tigera-operator
LABEL operators.operatorframework.io.metrics.builder=operator-sdk-v1.42.2
LABEL operators.operatorframework.io.metrics.mediatype.v1=metrics+v1

# Copy files to locations specified by labels.
COPY bundle/manifests /manifests/
COPY bundle/metadata /metadata/
`)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", bundleDir, err)
	}

	if err := updateDockerfile("1.42.6"); err != nil {
		t.Fatalf("updateDockerfile: %v", err)
	}

	if _, err := os.Stat(bundleDockerfile); !os.IsNotExist(err) {
		t.Errorf("%s is still there, want it moved into %s", bundleDockerfile, bundleDir)
	}
	want := `FROM scratch
# Core bundle labels.
LABEL operators.operatorframework.io.bundle.package.v1=tigera-operator
# Copy files to locations specified by labels.
LABEL com.redhat.openshift.versions="v4.16-v4.18"
LABEL com.redhat.delivery.backport=true
LABEL com.redhat.delivery.operator.bundle=true
COPY 1.42.6/manifests /manifests/
COPY 1.42.6/metadata /metadata/
`
	if got := readFile(t, filepath.Join(bundleDir, "bundle-v1.42.6.Dockerfile")); got != want {
		t.Errorf("Dockerfile is\n%s\nwant\n%s", got, want)
	}
}

func TestUpdateAnnotations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "annotations.yaml")
	writeFile(t, path, `annotations:
  # Core bundle annotations.
  operators.operatorframework.io.bundle.package.v1: tigera-operator

  operators.operatorframework.io.metrics.builder: operator-sdk-v1.42.2
`)

	if err := updateAnnotations(path); err != nil {
		t.Fatalf("updateAnnotations: %v", err)
	}

	want := `annotations:
  # Core bundle annotations.
  operators.operatorframework.io.bundle.package.v1: tigera-operator
  com.redhat.openshift.versions: v4.16-v4.18
`
	if got := readFile(t, path); got != want {
		t.Errorf("annotations are\n%s\nwant\n%s", got, want)
	}
}

// TestUpdateCSV covers the build-time values as a whole, since which of them the
// CSV ends up with depends on the previous version and the architectures built.
func TestUpdateCSV(t *testing.T) {
	t.Parallel()

	const doc = `metadata:
  name: tigera-operator.v0.0.0
  annotations:
    capabilities: Seamless Upgrades
spec:
  displayName: Tigera Operator
  install:
    spec:
      deployments:
        - spec:
            template:
              spec:
                containers:
                  - name: tigera-operator
                    image: quay.io/tigera/operator:v0.0.0
      permissions:
        - serviceAccountName: tigera-operator
  version: 1.42.6
`
	img := image{
		digest:        "quay.io/tigera/operator@sha256:bbb",
		created:       "2026-01-02T03:04:05Z",
		architectures: []string{"amd64", "arm64"},
	}

	cases := []struct {
		name        string
		prevVersion string
		absent      string
		want        []string
	}{
		{
			name:        "replaces the previous version",
			prevVersion: "1.42.5",
			want:        []string{"replaces: tigera-operator.v1.42.5"},
		},
		{
			name:        "replaces nothing",
			prevVersion: noPreviousVersion,
			absent:      "replaces:",
			want: []string{
				"containerImage: quay.io/tigera/operator@sha256:bbb",
				`createdAt: "2026-01-02T03:04:05Z"`,
				"olm.skipRange: <1.42.6",
				"operatorframework.io/arch.amd64: supported",
				"operatorframework.io/arch.arm64: supported",
				"displayName: Tigera Operator v1.42",
				"image: quay.io/tigera/operator@sha256:bbb",
				"- name: tigera-operator\n      image: quay.io/tigera/operator@sha256:bbb",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), csvName)
			writeFile(t, path, doc)

			if err := updateCSV(path, "1.42.6", tc.prevVersion, img); err != nil {
				t.Fatalf("updateCSV: %v", err)
			}

			content := readFile(t, path)
			for _, want := range tc.want {
				assertContains(t, content, want)
			}
			if tc.absent != "" {
				assertNotContains(t, content, tc.absent)
			}
			// Empty permissions fail CSV validation, so they are always dropped.
			assertNotContains(t, content, "permissions:")
		})
	}
}

func encode(content string) string {
	return base64.StdEncoding.EncodeToString([]byte(content))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(content)
}

func assertContains(t *testing.T, content, want string) {
	t.Helper()

	if !strings.Contains(content, want) {
		t.Errorf("content does not contain %q:\n%s", want, content)
	}
}

func assertNotContains(t *testing.T, content, unwanted string) {
	t.Helper()

	if strings.Contains(content, unwanted) {
		t.Errorf("content contains %q:\n%s", unwanted, content)
	}
}
