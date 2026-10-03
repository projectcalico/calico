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
		"operator.yaml":                    "manifests/ocp-tigera-operator-no-resource-loading.yaml",
		"role.yaml":                        "manifests/ocp/02-role-tigera-operator.yaml",
		"rolebinding-tigera-operator.yaml": "manifests/ocp/02-rolebinding-tigera-operator.yaml",
		"03-cr-installation.yaml":          "manifests/ocp/03-cr-installation.yaml",
		"operator_v1_imageset.yaml":        "operator/config/samples/operator_v1_imageset.yaml",
	}
	wantCRDs := map[string]string{}
	for _, crd := range operatorCRDs {
		wantCRDs[crd] = "operator/pkg/crds/operator/" + crd
	}
	for _, resource := range calicoResources {
		name := "crd.projectcalico.org_" + resource + ".yaml"
		wantCRDs[name] = "libcalico-go/config/crd/" + name
	}
	for _, sources := range []map[string]string{wantDeploy, wantCRDs} {
		for _, src := range sources {
			path := filepath.Join(repoRoot, src)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("creating %s: %v", filepath.Dir(path), err)
			}
			writeFile(t, path, src)
		}
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

// assertStaged checks that dir holds exactly the wanted files, each copied from
// the source it is mapped to.
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

	for name, src := range want {
		if content := readFile(t, filepath.Join(dir, name)); content != src {
			t.Errorf("%s was copied from %s, want %s", name, content, src)
		}
	}
}
