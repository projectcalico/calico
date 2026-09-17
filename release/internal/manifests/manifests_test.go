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

package manifests

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
)

type call struct {
	name string
	args []string
	env  []string
}

// fakeRunner records every invocation and can fail a named command.
type fakeRunner struct {
	mu    sync.Mutex
	calls []call
	// failOn fails any command whose name matches.
	failOn string
}

func (f *fakeRunner) RunInDir(_, name string, args, env []string) (string, error) {
	return f.record(name, args, env)
}

func (f *fakeRunner) RunInDirToFile(_, name string, args, env []string, _ string) (string, error) {
	return f.record(name, args, env)
}

func (f *fakeRunner) Run(name string, args, env []string) (string, error) {
	return f.record(name, args, env)
}

func (f *fakeRunner) RunToFile(name string, args, env []string, _ string) (string, error) {
	return f.record(name, args, env)
}

func (f *fakeRunner) RunInDirNoCapture(_, name string, args, env []string) error {
	_, err := f.record(name, args, env)
	return err
}

func (f *fakeRunner) RunNoCapture(name string, args, env []string) error {
	return f.RunInDirNoCapture("", name, args, env)
}

func (f *fakeRunner) record(name string, args, env []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{name: name, args: args, env: env})
	if f.failOn != "" && name == f.failOn {
		return "boom", fmt.Errorf("%s failed", name)
	}
	return "", nil
}

func (f *fakeRunner) named(name string) []call {
	var out []call
	for _, c := range f.calls {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

// Product-neutral: enterprise replaces Files and the image names, so a test
// pinned to this product's strings fails there for no real reason.
const (
	productVersion  = "v9.9.9"
	operatorVersion = "v8.8.8"
	operatorImage   = "operator"
	testRegistry    = "registry.example/org"
	productRegistry = "registry.example/product"
)

func productImage(ver string) string {
	return testRegistry + "/product:" + ver
}

func operatorRef(ver string) string {
	return testRegistry + "/" + operatorImage + ":" + ver
}

func testManifests(t *testing.T) Manifests {
	t.Helper()
	return Manifests{
		RepoRoot:  t.TempDir(),
		Version:   productVersion,
		Operator:  registry.Component{Version: operatorVersion, Image: operatorImage, Registry: testRegistry},
		OutputDir: t.TempDir(),
	}
}

// The make target is faked, so the bundle it would have produced is written by
// hand for the collection step to find.
func writeBundle(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, ocpBundleTarget)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeManifest(t *testing.T, root, name string, images ...string) {
	t.Helper()
	path := filepath.Join(root, DirName, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n")
	for _, img := range images {
		fmt.Fprintf(&b, "    - image: %s\n", img)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func madeTarget(r *fakeRunner, target string) bool {
	for _, c := range r.named("make") {
		if slices.Contains(c.args, target) {
			return true
		}
	}
	return false
}

func TestBuild(t *testing.T) {
	t.Run("generates and collects", func(t *testing.T) {
		r := &fakeRunner{}
		if err := Build(testManifests(t), true, false, WithRunner(r), WithCollect()); err != nil {
			t.Fatalf("Build: %v", err)
		}
		if !madeTarget(r, generateTarget) {
			t.Error("expected the manifests to be generated")
		}
		if got := len(r.named("rsync")); got != 1 {
			t.Errorf("expected the manifests to be collected once, got %d", got)
		}
		if madeTarget(r, ocpBundleTarget) {
			t.Error("expected no OCP bundle")
		}
	})

	// A release ships the checked-in manifests: it must not regenerate, and it
	// must still get a bundle.
	t.Run("builds the bundle without generating", func(t *testing.T) {
		r := &fakeRunner{}
		m := testManifests(t)
		writeBundle(t, m.RepoRoot)
		if err := Build(m, false, true, WithRunner(r)); err != nil {
			t.Fatalf("Build: %v", err)
		}
		if madeTarget(r, generateTarget) {
			t.Error("expected no manifest generation")
		}
		if len(r.named("rsync")) != 0 {
			t.Error("expected no manifests copy")
		}
		if !madeTarget(r, ocpBundleTarget) {
			t.Error("expected the OCP bundle to be built")
		}
		if _, err := os.Stat(BundlePath(m.OutputDir)); err != nil {
			t.Errorf("expected the bundle to be collected: %v", err)
		}
	})

	t.Run("resets the tree when generation fails", func(t *testing.T) {
		r := &fakeRunner{failOn: "make"}
		if err := Build(testManifests(t), true, false, WithRunner(r)); err == nil {
			t.Fatal("expected generation to fail")
		}
		reset := r.named("git")
		if len(reset) != 1 {
			t.Fatalf("expected the tree to be reset once, got %d resets", len(reset))
		}
		if !slices.Contains(reset[0].args, "checkout") {
			t.Errorf("expected a checkout, got %v", reset[0].args)
		}
		for _, tree := range generatedTrees {
			if !slices.Contains(reset[0].args, tree) {
				t.Errorf("expected %s to be restored, got %v", tree, reset[0].args)
			}
		}
	})

	t.Run("sends the versions the script reads", func(t *testing.T) {
		r := &fakeRunner{}
		m := testManifests(t)
		m.Registry = productRegistry
		if err := Build(m, true, false, WithRunner(r)); err != nil {
			t.Fatalf("Build: %v", err)
		}
		want := map[string]string{
			utils.EnvProductVersion:           productVersion,
			utils.EnvOperatorVersion:          operatorVersion,
			utils.EnvOperatorRegistryOverride: testRegistry,
			utils.EnvOperatorImageOverride:    operatorImage,
			utils.EnvRegistry:                 productRegistry,
		}
		env := r.named("make")[0].env
		for k, v := range want {
			if !slices.Contains(env, k+"="+v) {
				t.Errorf("expected %s=%s in the environment", k, v)
			}
		}
	})

	// An empty registry leaves whatever the manifests already carry, so the
	// variable must be absent rather than set to an empty string.
	t.Run("always exports the registry", func(t *testing.T) {
		r := &fakeRunner{}
		m := testManifests(t)
		m.Registry = productRegistry
		if err := Build(m, true, false, WithRunner(r)); err != nil {
			t.Fatalf("Build: %v", err)
		}
		if !slices.Contains(r.named("make")[0].env, utils.EnvRegistry+"="+productRegistry) {
			t.Errorf("expected %s=%s in the environment", utils.EnvRegistry, productRegistry)
		}
	})

	t.Run("excludes repo mechanics from the copy", func(t *testing.T) {
		r := &fakeRunner{}
		m := testManifests(t)
		if err := Build(m, true, false, WithRunner(r), WithCollect()); err != nil {
			t.Fatalf("Build: %v", err)
		}
		args := r.named("rsync")[0].args
		for _, name := range excluded {
			if !slices.Contains(args, "--exclude="+name) {
				t.Errorf("expected %s to be excluded, got %v", name, args)
			}
		}
		if got := args[len(args)-1]; got != Dir(m.OutputDir)+"/" {
			t.Errorf("expected the destination to be %s, got %s", Dir(m.OutputDir), got)
		}
	})

	t.Run("the environment is a replacement point", func(t *testing.T) {
		original := Env
		t.Cleanup(func() { Env = original })
		Env = func(m Manifests) []string {
			return append(original(m), "EXTRA=set")
		}
		r := &fakeRunner{}
		if err := Build(testManifests(t), true, false, WithRunner(r)); err != nil {
			t.Fatalf("Build: %v", err)
		}
		env := r.named("make")[0].env
		if !slices.Contains(env, "EXTRA=set") {
			t.Error("expected the override's addition")
		}
		if !slices.Contains(env, utils.EnvProductVersion+"="+productVersion) {
			t.Error("expected the shared environment to survive the override")
		}
	})

	t.Run("validation", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			mutate   func(*Manifests)
			generate bool
			wantErr  string
		}{
			{
				name:     "no version",
				mutate:   func(m *Manifests) { m.Version = "" },
				generate: true,
				wantErr:  "no version specified",
			},
			{
				name:     "generating without an operator version",
				mutate:   func(m *Manifests) { m.Operator.Version = "" },
				generate: true,
				wantErr:  "no operator version specified",
			},
			{
				name:    "no output directory",
				mutate:  func(m *Manifests) { m.OutputDir = "" },
				wantErr: "no output directory specified",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				m := testManifests(t)
				tc.mutate(&m)
				err := Build(m, tc.generate, false, WithRunner(&fakeRunner{}))
				if err == nil {
					t.Fatalf("expected an error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected %q, got %v", tc.wantErr, err)
				}
			})
		}
	})
}

func TestAssertVersions(t *testing.T) {
	t.Run("image versions", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			images  []string
			wantErr string
		}{
			{
				name:   "product and operator images at their own versions",
				images: []string{productImage(productVersion), operatorRef(operatorVersion)},
			},
			{
				name:    "product image at the wrong version",
				images:  []string{productImage("v0.0.1")},
				wantErr: "expected " + productVersion,
			},
			{
				// The grep version skipped anything containing "operator", so a
				// mis-pinned operator passed silently.
				name:    "operator image at the wrong version",
				images:  []string{operatorRef("v0.0.1")},
				wantErr: "expected " + operatorVersion,
			},
			{
				// An image whose name ends in the operator's carries the
				// product version, so a substring match would fail it.
				name:   "operator-adjacent image at the product version",
				images: []string{testRegistry + "/metrics-" + operatorImage + ":" + productVersion},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				m := testManifests(t)
				for _, name := range Files() {
					writeManifest(t, m.RepoRoot, name, tc.images...)
				}
				err := AssertVersions(m, WithRunner(&fakeRunner{}))
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("AssertVersions: %v", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("expected an error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected %q, got %v", tc.wantErr, err)
				}
			})
		}
	})

	// The subset is deliberate: widening it is a behaviour change.
	t.Run("reads only its file list", func(t *testing.T) {
		m := testManifests(t)
		for _, name := range Files() {
			writeManifest(t, m.RepoRoot, name, productImage(productVersion))
		}
		writeManifest(t, m.RepoRoot, "not-in-the-list.yaml", productImage("v0.0.1"))
		if err := AssertVersions(m, WithRunner(&fakeRunner{})); err != nil {
			t.Fatalf("AssertVersions: %v", err)
		}
	})

	t.Run("needs an operator image to check against", func(t *testing.T) {
		m := testManifests(t)
		m.Operator.Image = ""
		err := AssertVersions(m, WithRunner(&fakeRunner{}))
		if err == nil || !strings.Contains(err.Error(), "no operator image specified") {
			t.Errorf("expected a missing operator image error, got %v", err)
		}
	})
}

func TestPaths(t *testing.T) {
	t.Run("the output directory is named once", func(t *testing.T) {
		if got, want := Dir("/out"), filepath.Join("/out", DirName); got != want {
			t.Errorf("Dir = %s, want %s", got, want)
		}
	})

	// Excluded is the archive's filter; it and the rsync must agree on what
	// ships, or the two release paths diverge.
	t.Run("the archive filter matches the rsync exclusions", func(t *testing.T) {
		for _, name := range excluded {
			if Include("", "", name) {
				t.Errorf("expected %s to be filtered out", name)
			}
		}
		for _, name := range Files() {
			if !Include("", "", name) {
				t.Errorf("expected %s to ship", name)
			}
		}
	})
}

func TestRegistry(t *testing.T) {
	write := func(t *testing.T, root, image string) {
		t.Helper()
		writeManifest(t, root, RegistryFile, image)
	}

	t.Run("reads the registry the manifests carry", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, testRegistry+"/"+registryImage+":"+productVersion)
		got, err := Registry(root)
		if err != nil {
			t.Fatalf("Registry: %v", err)
		}
		if got != testRegistry {
			t.Errorf("Registry = %q, want %q", got, testRegistry)
		}
	})

	// An image with no registry segment reads as empty rather than an error,
	// which is how the manager's reader has always behaved.
	t.Run("reports no registry for an unqualified image", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, registryImage+":"+productVersion)
		got, err := Registry(root)
		if err != nil {
			t.Fatalf("Registry: %v", err)
		}
		if got != "" {
			t.Errorf("Registry = %q, want empty", got)
		}
	})

	t.Run("errors when the file is missing", func(t *testing.T) {
		if _, err := Registry(t.TempDir()); err == nil {
			t.Error("expected an error for a missing manifest")
		}
	})
}
