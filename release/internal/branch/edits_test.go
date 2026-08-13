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

package branch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func TestApplyEdits(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "metadata.mk", "OPERATOR_BRANCH ?= master\n")

	edits := []Edit{
		{File: "metadata.mk", Pattern: `^OPERATOR_BRANCH.*`, Replacement: "OPERATOR_BRANCH ?= release-v1.40"},
		{File: "gone/absent.sh", Pattern: `x`, Replacement: "y"}, // missing file -> skipped
	}

	written, skipped, err := ApplyEdits(root, edits)
	require.NoError(t, err)
	require.Equal(t, []string{"metadata.mk"}, written)
	require.Contains(t, skipped[0], "gone/absent.sh")

	got, _ := os.ReadFile(filepath.Join(root, "metadata.mk"))
	require.Equal(t, "OPERATOR_BRANCH ?= release-v1.40\n", string(got))

	// idempotent: second run writes nothing new, no error, file unchanged
	written, _, err = ApplyEdits(root, edits)
	require.NoError(t, err)
	require.Empty(t, written)
	got2, _ := os.ReadFile(filepath.Join(root, "metadata.mk"))
	require.Equal(t, "OPERATOR_BRANCH ?= release-v1.40\n", string(got2))

	// required + missing -> error
	_, _, err = ApplyEdits(root, []Edit{{File: "nope", Pattern: "a", Replacement: "b", Required: true}})
	require.Error(t, err)
}

// TestApplyEditsCaptureGroupIdempotent: a capture-group Replacement (the mocknode
// tag edit) must register done on the second run, writing nothing.
func TestApplyEditsCaptureGroupIdempotent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "mock-node.yaml", "  image: docker.io/calico/mock-node:master\n")

	edits := []Edit{{
		File:        "mock-node.yaml",
		Pattern:     `([a-zA-Z .]+)([a-zA-Z.]+/mock-node:)[^[:space:]]+`,
		Replacement: `${1}${2}release-v1.40`,
	}}

	written, _, err := ApplyEdits(root, edits)
	require.NoError(t, err)
	require.Equal(t, []string{"mock-node.yaml"}, written)
	got, _ := os.ReadFile(filepath.Join(root, "mock-node.yaml"))
	require.Equal(t, "  image: docker.io/calico/mock-node:release-v1.40\n", string(got))

	// Second run: the expansion is already present, so the edit is done and
	// writes nothing.
	written, _, err = ApplyEdits(root, edits)
	require.NoError(t, err)
	require.Empty(t, written, "a capture-group edit already applied must register done")
}
