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
	"os"
	"path/filepath"
	"testing"
)

func TestDocumentSet(t *testing.T) {
	t.Parallel()

	const doc = `metadata:
  annotations:
    createdAt: "2020-01-01T00:00:00Z"
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
                    image: quay.io/tigera/operator:v1.0.0
      permissions:
        - serviceAccountName: tigera-operator
`

	cases := []struct {
		name  string
		path  []any
		value string
		want  string
	}{
		{
			name:  "overwrites an existing key",
			path:  []any{"metadata", "annotations", "createdAt"},
			value: "2026-01-01T00:00:00Z",
			want: `metadata:
  annotations:
    createdAt: "2026-01-01T00:00:00Z"
`,
		},
		{
			name:  "adds a key to an existing mapping",
			path:  []any{"metadata", "annotations", "olm.skipRange"},
			value: "<1.42.6",
			want: `    createdAt: "2020-01-01T00:00:00Z"
    olm.skipRange: <1.42.6
`,
		},
		{
			name:  "creates a missing mapping",
			path:  []any{"metadata", "labels", "operatorframework.io/arch.arm64"},
			value: "supported",
			want: `  labels:
    operatorframework.io/arch.arm64: supported
`,
		},
		{
			name:  "creates a missing sequence",
			path:  []any{"spec", "relatedImages", 0, "name"},
			value: "tigera-operator",
			want: `  relatedImages:
    - name: tigera-operator
`,
		},
		{
			name:  "walks into a sequence",
			path:  []any{"spec", "install", "spec", "deployments", 0, "spec", "template", "spec", "containers", 0, "image"},
			value: "quay.io/tigera/operator@sha256:abc",
			want:  `                    image: quay.io/tigera/operator@sha256:abc`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := writeDocument(t, doc)
			if err := d.set(tc.value, tc.path...); err != nil {
				t.Fatalf("set(%v): %v", tc.path, err)
			}
			if err := d.save(); err != nil {
				t.Fatalf("save: %v", err)
			}
			assertContains(t, readFile(t, d.path), tc.want)
		})
	}
}

func TestDocumentSetErrors(t *testing.T) {
	t.Parallel()

	const doc = `spec:
  displayName: Tigera Operator
  relatedImages:
    - name: tigera-operator
`

	cases := []struct {
		name string
		path []any
	}{
		{name: "no path", path: nil},
		{name: "index into a scalar", path: []any{"spec", "displayName", 0, "name"}},
		{name: "key of a sequence", path: []any{"spec", "relatedImages", "name"}},
		{name: "index past the end", path: []any{"spec", "relatedImages", 2, "name"}},
		{name: "sequence index last", path: []any{"spec", "relatedImages", 0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := writeDocument(t, doc)
			if err := d.set("value", tc.path...); err == nil {
				t.Fatalf("set(%v) succeeded, want an error", tc.path)
			}
		})
	}
}

func TestDocumentDelete(t *testing.T) {
	t.Parallel()

	const doc = `spec:
  install:
    spec:
      permissions:
        - serviceAccountName: tigera-operator
      clusterPermissions:
        - serviceAccountName: tigera-operator
`

	cases := []struct {
		name    string
		path    []any
		absent  string
		present string
	}{
		{
			name:    "deletes a key",
			path:    []any{"spec", "install", "spec", "permissions"},
			absent:  "      permissions:",
			present: "      clusterPermissions:",
		},
		{
			name:    "a missing key is not an error",
			path:    []any{"spec", "install", "spec", "webhookdefinitions"},
			present: "      permissions:",
		},
		{
			name:    "a missing parent is not an error",
			path:    []any{"spec", "customresourcedefinitions", "owned"},
			present: "      permissions:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := writeDocument(t, doc)
			if err := d.delete(tc.path...); err != nil {
				t.Fatalf("delete(%v): %v", tc.path, err)
			}
			if err := d.save(); err != nil {
				t.Fatalf("save: %v", err)
			}
			content := readFile(t, d.path)
			if tc.absent != "" {
				assertNotContains(t, content, tc.absent)
			}
			assertContains(t, content, tc.present)
		})
	}
}

// TestDocumentPreservesTheRest checks that an update rewrites the fields it was
// asked for and leaves the rest of the document - key order, comments and
// scalar styles - as it found it.
func TestDocumentPreservesTheRest(t *testing.T) {
	t.Parallel()

	const doc = `# A leading comment.
spec:
  displayName: Tigera Operator
  description: |-
    A literal block
    over two lines.
  version: 0.0.0
`

	d := writeDocument(t, doc)
	if err := d.set("Tigera Operator v1.42", "spec", "displayName"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := d.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	want := `# A leading comment.
spec:
  displayName: Tigera Operator v1.42
  description: |-
    A literal block
    over two lines.
  version: 0.0.0
`
	if got := readFile(t, d.path); got != want {
		t.Errorf("document is\n%s\nwant\n%s", got, want)
	}
}

func writeDocument(t *testing.T, content string) *document {
	t.Helper()

	path := filepath.Join(t.TempDir(), "doc.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	d, err := loadDocument(path)
	if err != nil {
		t.Fatalf("loading %s: %v", path, err)
	}
	return d
}
