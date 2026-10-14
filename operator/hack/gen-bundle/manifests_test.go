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
	"slices"
	"testing"
)

// TestGetManifests stages from a fake repository in which every source file
// holds its own path, so that each staged file can be traced to where it came
// from. It also covers leftovers from an earlier run, which operator-sdk would
// otherwise pick up.
func TestGetManifests(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	wantDeploy := map[string]string{
		"operator.yaml":                     "manifests/ocp-tigera-operator-no-resource-loading.yaml",
		"role.yaml":                         "manifests/ocp/02-role-tigera-operator.yaml",
		"rolebinding-tigera-operator.yaml":  "manifests/ocp/02-rolebinding-tigera-operator.yaml",
		"role-tigera-operator-secrets.yaml": "manifests/ocp/02-role-tigera-operator-secrets.yaml",
		"03-cr-installation.yaml":           "manifests/ocp/03-cr-installation.yaml",
		"operator_v1_imageset.yaml":         "operator/config/samples/operator_v1_imageset.yaml",
	}
	wantCRDs := map[string]string{}
	for _, crd := range operatorCRDs {
		wantCRDs[crd] = "operator/pkg/crds/operator/" + crd
	}
	for _, resource := range calicoResources {
		name := "crd.projectcalico.org_" + resource + ".yaml"
		wantCRDs[name] = "libcalico-go/config/crd/" + name
	}
	// The secrets RBAC is edited on the way through, so its sources carry the
	// lines that are rewritten as well as their path.
	sources := map[string]string{
		"manifests/ocp/02-role-tigera-operator-secrets.yaml":        "manifests/ocp/02-role-tigera-operator-secrets.yaml\nkind: ClusterRole\nmetadata:\n  name: tigera-operator-secrets\n",
		"manifests/ocp/02-rolebinding-tigera-operator-secrets.yaml": "manifests/ocp/02-rolebinding-tigera-operator-secrets.yaml\nkind: RoleBinding\nmetadata:\n  name: tigera-operator-secrets\nroleRef:\n  kind: ClusterRole\n  name: tigera-operator-secrets\n",
	}
	for _, staged := range []map[string]string{wantDeploy, wantCRDs} {
		for name, src := range staged {
			if content, ok := sources[src]; ok {
				staged[name] = content
				continue
			}
			sources[src] = src
		}
	}
	// The ClusterRole is also staged as a namespaced Role, with the binding
	// pointed at that Role rather than at the ClusterRole.
	wantDeploy["role-tigera-operator-secrets-namespaced.yaml"] = "manifests/ocp/02-role-tigera-operator-secrets.yaml\nkind: Role\nmetadata:\n  name: tigera-operator-secrets-namespaced\n"
	wantDeploy["rolebinding-tigera-operator-secrets.yaml"] = "manifests/ocp/02-rolebinding-tigera-operator-secrets.yaml\nkind: RoleBinding\nmetadata:\n  name: tigera-operator-secrets-namespaced\nroleRef:\n  kind: Role\n  name: tigera-operator-secrets-namespaced\n"
	for src, content := range sources {
		path := filepath.Join(repoRoot, src)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(path), err)
		}
		writeFile(t, path, content)
	}

	staging := t.TempDir()
	crdDir := filepath.Join(staging, "crds")
	deployDir := filepath.Join(staging, "deploy")
	for _, dir := range []string{crdDir, deployDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("creating %s: %v", dir, err)
		}
		writeFile(t, filepath.Join(dir, "stale.yaml"), "left over from an earlier run")
	}

	if err := getManifests(repoRoot, crdDir, deployDir); err != nil {
		t.Fatalf("getManifests: %v", err)
	}

	assertStaged(t, deployDir, wantDeploy)
	assertStaged(t, crdDir, wantCRDs)
}

func TestGetManifestsWithMissingSource(t *testing.T) {
	t.Parallel()

	staging := t.TempDir()
	err := getManifests(t.TempDir(), filepath.Join(staging, "crds"), filepath.Join(staging, "deploy"))
	if err == nil {
		t.Fatal("getManifests from an empty repository succeeded, want an error")
	}
}

// TestGetManifestsWontClearASourceTree checks that a staging directory holding
// anything get-manifests would not have staged is left alone.
func TestGetManifestsWontClearASourceTree(t *testing.T) {
	t.Parallel()

	for name, entry := range map[string]string{
		"a non-YAML file": "main.go",
		"a subdirectory":  "pkg/crd.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			staging := t.TempDir()
			deployDir := filepath.Join(staging, "deploy")
			kept := filepath.Join(deployDir, entry)
			if err := os.MkdirAll(filepath.Dir(kept), 0o755); err != nil {
				t.Fatalf("creating %s: %v", filepath.Dir(kept), err)
			}
			writeFile(t, kept, "not ours")

			if err := getManifests(t.TempDir(), filepath.Join(staging, "crds"), deployDir); err == nil {
				t.Fatal("getManifests succeeded, want an error")
			}
			if _, err := os.Stat(kept); err != nil {
				t.Errorf("%s was removed: %v", kept, err)
			}
		})
	}
}

// TestReplaceLines checks that a file which no longer looks the way the secrets
// RBAC staging expects fails the build, rather than staging a binding that
// still claims the ClusterRole.
func TestReplaceLines(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, content string
		wantErr       bool
	}{
		{"expected matches", "a\nkind: ClusterRole\n", false},
		{"no match", "a\n  kind: ClusterRole\n", true},
		{"too many matches", "kind: ClusterRole\nkind: ClusterRole\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "role.yaml")
			writeFile(t, path, tc.content)
			err := replaceLines(path, lineEdit{"kind: ClusterRole", "kind: Role", 1})
			if (err != nil) != tc.wantErr {
				t.Fatalf("replaceLines error = %v, want error: %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if got := readFile(t, path); got != "a\nkind: Role\n" {
					t.Errorf("replaceLines wrote %q", got)
				}
			}
		})
	}
}

// assertStaged checks that dir holds exactly the wanted files, each with the
// content it is mapped to.
func assertStaged(t *testing.T, dir string, want map[string]string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	var wantNames []string
	for name := range want {
		wantNames = append(wantNames, name)
	}
	slices.Sort(wantNames)
	if !slices.Equal(got, wantNames) {
		t.Errorf("%s holds %v, want %v", dir, got, wantNames)
	}

	for name, wantContent := range want {
		if content := readFile(t, filepath.Join(dir, name)); content != wantContent {
			t.Errorf("%s holds %q, want %q", name, content, wantContent)
		}
	}
}
