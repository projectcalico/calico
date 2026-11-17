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

package binaries

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/outputs"
)

func writeE2EConfig(t *testing.T, repoRoot string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(repoRoot, E2EComponent, "config", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func readConfigArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("close archive: %v", err)
		}
	})
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	got := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		got[hdr.Name] = string(body)
	}
}

func TestPackageE2EConfigKeepsTheTree(t *testing.T) {
	repoRoot, outputDir := t.TempDir(), t.TempDir()
	writeE2EConfig(t, repoRoot, map[string]string{
		"base.yaml":                      "base",
		"iptables/xtables-manifest.yaml": "extends: ../base.yaml",
		"kind/deep/nested.yaml":          "nested",
	})
	want := map[string]string{
		"config/base.yaml":                      "base",
		"config/iptables/xtables-manifest.yaml": "extends: ../base.yaml",
		"config/kind/deep/nested.yaml":          "nested",
	}

	if err := PackageE2EConfig(repoRoot, outputDir); err != nil {
		t.Fatalf("PackageE2EConfig: %v", err)
	}
	wantPath := filepath.Join(outputDir, outputs.FilesDirName, E2EComponent, "config.tar.gz")
	if got := E2EConfigPath(outputDir); got != wantPath {
		t.Errorf("E2EConfigPath = %s, want %s", got, wantPath)
	}
	if got := readConfigArchive(t, wantPath); !maps.Equal(got, want) {
		t.Errorf("archive holds %v, want %v", got, want)
	}
}

func TestPackageE2EConfigIsReproducible(t *testing.T) {
	repoRoot := t.TempDir()
	writeE2EConfig(t, repoRoot, map[string]string{
		"a.yaml":   "a",
		"b/c.yaml": "c",
	})
	first, second := t.TempDir(), t.TempDir()
	for _, out := range []string{first, second} {
		if err := PackageE2EConfig(repoRoot, out); err != nil {
			t.Fatalf("PackageE2EConfig: %v", err)
		}
	}
	a, err := os.ReadFile(E2EConfigPath(first))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(E2EConfigPath(second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two archives of the same tree differ")
	}
}

func TestPackageE2EConfigFailsWithoutConfigs(t *testing.T) {
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, E2EComponent, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]string{
		"missing": t.TempDir(),
		"empty":   empty,
	} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			err := PackageE2EConfig(root, out)
			if err == nil {
				t.Fatal("PackageE2EConfig succeeded, want an error")
			}
			if !strings.Contains(err.Error(), filepath.Join(E2EComponent, "config")) {
				t.Errorf("error %q does not name the config directory", err)
			}
			if _, statErr := os.Stat(E2EConfigPath(out)); statErr == nil {
				t.Error("left an archive behind after failing")
			}
		})
	}
	if err := PackageE2EConfig("", t.TempDir()); err == nil {
		t.Error("PackageE2EConfig with no repo root succeeded, want an error")
	}
}

func TestPackageE2EConfigRejectsSymlinks(t *testing.T) {
	repoRoot, out := t.TempDir(), t.TempDir()
	writeE2EConfig(t, repoRoot, map[string]string{"base.yaml": "base"})
	link := filepath.Join(repoRoot, E2EComponent, "config", "linked.yaml")
	if err := os.Symlink("base.yaml", link); err != nil {
		t.Fatal(err)
	}

	err := PackageE2EConfig(repoRoot, out)
	if err == nil {
		t.Fatal("PackageE2EConfig succeeded, want an error for the symlink")
	}
	if !strings.Contains(err.Error(), "linked.yaml") {
		t.Errorf("error %q does not name the symlink", err)
	}
	if _, statErr := os.Stat(E2EConfigPath(out)); statErr == nil {
		t.Error("left an archive behind after failing")
	}
}
