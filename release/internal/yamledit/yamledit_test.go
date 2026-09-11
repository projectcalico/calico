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

package yamledit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every shape the editor has to survive, in one file.
const fixture = `# a heading comment
apiVersion: v2

tigeraOperator:
  image: calico/operator
  version: master # keep this comment
  registry: quay.io

calicoctl:
  image: quay.io/calico/calico
  tag: "master"

# version: commented out
notes: |
  version: in a block scalar
empty:
`

func TestApplyPreservesEverythingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit Edit
		want string
	}{
		{
			name: "key matched whole, not as a suffix",
			edit: Edit{Key: "version", To: "v3.30.0"},
			want: strings.NewReplacer(
				"  version: master # keep this comment", "  version: v3.30.0 # keep this comment",
			).Replace(fixture),
		},
		{
			name: "every depth the key appears at",
			edit: Edit{Key: "image", To: "x"},
			want: strings.NewReplacer(
				"  image: calico/operator", "  image: x",
				"  image: quay.io/calico/calico", "  image: x",
			).Replace(fixture),
		},
		{
			name: "quotes survive",
			edit: Edit{Key: "tag", To: "v3.30.0"},
			want: strings.Replace(fixture, `  tag: "master"`, `  tag: "v3.30.0"`, 1),
		},
		{
			name: "a path pins one of two matching keys",
			edit: Edit{Key: "tigeraOperator.image", To: "x"},
			want: strings.Replace(fixture, "  image: calico/operator", "  image: x", 1),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.edit.apply([]byte(fixture))
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("Apply produced:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

func TestApplyDoesNotMatchALongerKey(t *testing.T) {
	got, err := Edit{Key: "version", To: "v3.30.0"}.apply([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "apiVersion: v2") {
		t.Error("apiVersion was rewritten")
	}
}

func TestApplyLeavesCommentsAndBlockScalars(t *testing.T) {
	got, err := Edit{Key: "version", To: "v3.30.0"}.apply([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# version: commented out", "  version: in a block scalar"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("expected %q to survive", want)
		}
	}
}

func TestApplyWritesSpecialCharactersVerbatim(t *testing.T) {
	const to = `a~b&c/d.e`
	got, err := Edit{Key: "registry", To: to}.apply([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "  registry: "+to) {
		t.Errorf("expected %q written verbatim, got:\n%s", to, got)
	}
}

func TestApplyRejectsIncompleteEdits(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit Edit
	}{
		{"no replacement", Edit{Key: "version"}},
		{"no key", Edit{To: "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.edit.apply([]byte(fixture)); err == nil {
				t.Error("expected an incomplete edit to be rejected")
			}
		})
	}
}

func TestApplyRejectsMalformedYAML(t *testing.T) {
	if _, err := (Edit{Key: "version", To: "x"}).apply([]byte("a:\n\tb: 1\n")); err == nil {
		t.Error("expected a parse failure")
	}
}

func TestApplyRefusesToReplaceABlockScalar(t *testing.T) {
	if _, err := (Edit{Key: "notes", To: "x"}).apply([]byte(fixture)); err == nil {
		t.Error("expected a block scalar to be refused")
	}
}

func TestApplyToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyToFile(path, Edit{Key: "version", To: "v3.30.0"}, Edit{Key: "tag", To: "v3.30.0"}); err != nil {
		t.Fatalf("ApplyToFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "  version: v3.30.0 # keep this comment") {
		t.Error("first edit did not land")
	}
	if !strings.Contains(string(got), `  tag: "v3.30.0"`) {
		t.Error("second edit did not land")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %v, want 0600", got)
	}
}

func TestApplyToFileRejectsAnEditThatMatchesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ApplyToFile(path, Edit{Key: "renamed", To: "x"})
	if err == nil {
		t.Fatal("expected an edit matching nothing to fail")
	}
	if !strings.Contains(err.Error(), "renamed") {
		t.Errorf("error does not name the key: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != fixture {
		t.Error("the file was modified by a failed edit")
	}
}

func TestApplyScopesToADottedPath(t *testing.T) {
	got, err := Edit{Key: "tigeraOperator.image", To: "x"}.apply([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "  image: x") {
		t.Error("expected tigeraOperator.image replaced")
	}
	if !strings.Contains(string(got), "  image: quay.io/calico/calico") {
		t.Error("expected calicoctl.image left alone")
	}
}

func TestApplyBareKeyMatchesEveryDepth(t *testing.T) {
	got, err := Edit{Key: "image", To: "x"}.apply([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "calico/operator") || strings.Contains(string(got), "quay.io/calico/calico") {
		t.Errorf("a matching key was left behind:\n%s", got)
	}
}

func TestApplyKeyIsNotASubstring(t *testing.T) {
	if _, err := (Edit{Key: "Version", To: "x"}).apply([]byte(fixture)); err == nil {
		t.Error("expected no match: a key must not match inside a longer key")
	}
}

func TestApplyMatchesEveryKeyInOneMapping(t *testing.T) {
	const src = `spec:
  tag: master
  other: keep
`
	got, err := Edit{Key: "tag", To: "x"}.apply([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "  other: keep") {
		t.Error("expected the untargeted key untouched")
	}
}

// A duplicate key is legal YAML and both copies are values.
func TestApplyMatchesADuplicatedKey(t *testing.T) {
	got, err := Edit{Key: "tag", To: "x"}.apply([]byte("spec:\n  tag: one\n  tag: two\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "spec:\n  tag: x\n  tag: x\n"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestApplyMatchesAcrossSiblingMappings(t *testing.T) {
	const src = `first:
  tag: master
second:
  tag: master
third:
  tag: master
`
	got, err := Edit{Key: "tag", To: "x"}.apply([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "master") {
		t.Errorf("a sibling was left behind:\n%s", got)
	}
}

// A flow mapping keeps more than the value on its line, so the span must stop
// at the value rather than run to the end.
func TestApplyInAFlowMapping(t *testing.T) {
	got, err := Edit{Key: "tag", To: "X"}.apply([]byte("spec: {tag: a, other: b}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "spec: {tag: X, other: b}\n"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Every document is edited, not just the first.
func TestApplyAcrossDocuments(t *testing.T) {
	got, err := Edit{Key: "tag", To: "X"}.apply([]byte("tag: a\n---\ntag: b\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "tag: X\n---\ntag: X\n"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
