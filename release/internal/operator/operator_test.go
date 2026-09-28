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

package operator

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []call
	err   error
}

type call struct {
	args []string
	env  []string
}

func (f *fakeRunner) record(args, env []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{args: slices.Clone(args), env: slices.Clone(env)})
	return f.err
}

func (f *fakeRunner) Run(_ string, args, env []string) (string, error) {
	return "", f.record(args, env)
}

func (f *fakeRunner) RunNoCapture(_ string, args, env []string) error {
	return f.record(args, env)
}

func (f *fakeRunner) RunInDir(_, _ string, args, env []string) (string, error) {
	return "", f.record(args, env)
}

func (f *fakeRunner) RunInDirNoCapture(_, _ string, args, env []string) error {
	return f.record(args, env)
}

func (f *fakeRunner) RunInDirToFile(_, _ string, args, env []string, _ string) (string, error) {
	return "", f.record(args, env)
}

func (f *fakeRunner) targets() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, strings.Join(c.args, " "))
	}
	return out
}

// Variants() is overridable, so a verb test using it would assert the
// product's list rather than the verb.
func oneVariant() []Variant {
	return []Variant{{Name: standardVariant}}
}

func testOperator() Operator {
	return Operator{
		RepoRoot:        "/repo",
		Version:         "v1.44.0",
		Image:           registry.OperatorImage,
		Registries:      registry.DefaultOperatorRegistries,
		ProductVersion:  "v3.34.0",
		ProductRegistry: registry.DefaultProductRegistry,
	}
}

func oneRegistryOperator() Operator {
	o := testOperator()
	o.Registries = []string{"quay.io/a"}
	o.Image = "operator"
	return o
}

func envValue(env []string, name string) (string, bool) {
	prefix := name + "="
	// Last wins, as it does for the process the env is handed to.
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix), true
		}
	}
	return "", false
}

func TestOperator(t *testing.T) {
	t.Run("dir", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			o    Operator
			want string
		}{
			{name: "in tree", o: Operator{RepoRoot: "/repo"}, want: "/repo/operator"},
			{name: "no repo root", o: Operator{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if Dir(tc.o) != tc.want {
					t.Errorf("got %v, want %v", Dir(tc.o), tc.want)
				}
			})
		}
	})

	t.Run("registry", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			registries []string
			want       string
		}{
			{name: "first of several", registries: []string{"a.io/x", "b.io/x"}, want: "a.io/x"},
			{name: "only one", registries: []string{"a.io/x"}, want: "a.io/x"},
			{name: "none"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				o := testOperator()
				o.Registries = tc.registries
				if Registry(o) != tc.want {
					t.Errorf("got %v, want %v", Registry(o), tc.want)
				}
			})
		}
	})
}

func TestVariants(t *testing.T) {
	t.Run("well formed", func(t *testing.T) {
		got := Variants()
		if len(got) == 0 {
			t.Errorf("expected non-empty")
		}

		seen := map[string]bool{}
		var standard int
		for _, v := range got {
			if len(v.Name) == 0 {
				t.Errorf("expected non-empty")
			}
			if seen[v.Name] {
				t.Errorf("expected false")
			}
			seen[v.Name] = true
			if v.Name == standardVariant {
				standard++
				if len(v.Image) != 0 {
					t.Errorf("expected empty, got %v", v.Image)
				}
			} else {
				if len(v.Image) == 0 {
					t.Errorf("expected non-empty")
				}
			}
		}
		if standard != 1 {
			t.Errorf("got %v, want %v (exactly one variant is the standard one)", standard, 1)
		}
	})

	t.Run("env overrides the environment", func(t *testing.T) {
		t.Setenv("VARIANT", "inherited")
		f := &fakeRunner{}
		variants := []Variant{{Name: "alt", Image: "operator-alt", Env: []string{"VARIANT=alt"}}}
		if err := Build(testOperator(), variants, false, WithRunner(f), WithValidation(false)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(f.calls) != 1 {
			t.Fatalf("len = %d, want 1", len(f.calls))
		}
		got, ok := envValue(f.calls[0].env, "VARIANT")
		if !(ok) {
			t.Errorf("expected true")
		}
		if got != "alt" {
			t.Errorf("got %v, want %v", got, "alt")
		}
	})

	// Each variant's make runs in the same tree, where a concurrent clean or tool
	// download breaks the other.
	t.Run("run one at a time", func(t *testing.T) {
		f := &overlapRunner{}
		variants := []Variant{{Name: standardVariant}, {Name: "alt", Image: "operator-alt"}}
		if err := Build(testOperator(), variants, false, WithRunner(f), WithValidation(false)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.overlapped.Load() {
			t.Error("variants ran at the same time")
		}
	})

	t.Run("component reads the variant image", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			v    Variant
			want string
		}{
			{name: "standard takes the operator image", v: Variant{Name: standardVariant}, want: registry.OperatorImage},
			{name: "a variant names its own", v: Variant{Name: "alt", Image: "operator-alt"}, want: "operator-alt"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if Component(testOperator(), tc.v).Image != tc.want {
					t.Errorf("got %v, want %v", Component(testOperator(), tc.v).Image, tc.want)
				}
			})
		}
	})

	t.Run("narrow", func(t *testing.T) {
		all := []Variant{{Name: standardVariant}, {Name: "alt"}}
		for _, tc := range []struct {
			name  string
			names []string
			want  []Variant
		}{
			{name: "no names leaves the set whole", want: all},
			{name: "one name", names: []string{"alt"}, want: []Variant{{Name: "alt"}}},
			{name: "every name", names: []string{standardVariant, "alt"}, want: all},
			{name: "unknown name", names: []string{"nope"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := Narrow(all, tc.names)
				if len(tc.want) == 0 {
					if len(got) != 0 {
						t.Errorf("expected empty, got %v", got)
					}
					return
				}
				if diff := cmp.Diff(tc.want, got); diff != "" {
					t.Errorf("Narrow() mismatch (-want +got):\n%s", diff)
				}
			})
		}
	})
}

func TestProductEnv(t *testing.T) {
	// The operator bakes the product it deploys into its binary, so every value
	// productEnv names has to survive into the make call.
	t.Run("reaches the build", func(t *testing.T) {
		for _, hashrelease := range []bool{true, false} {
			t.Run(fmt.Sprintf("hashrelease=%v", hashrelease), func(t *testing.T) {
				f := &fakeRunner{}
				if err := Build(testOperator(), oneVariant(), hashrelease, WithRunner(f), WithValidation(false)); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if len(f.calls) != 1 {
					t.Fatalf("len = %d, want 1", len(f.calls))
				}
				want, err := productEnv(testOperator())
				if err != nil {
					t.Fatalf("productEnv: %v", err)
				}
				if len(want) == 0 {
					t.Fatal("productEnv named nothing")
				}
				for _, e := range want {
					name, value, _ := strings.Cut(e, "=")
					got, ok := envValue(f.calls[0].env, name)
					if !ok {
						t.Errorf("%s is missing", name)
						continue
					}
					if got != value {
						t.Errorf("%s = %q, want %q", name, got, value)
					}
				}
			})
		}
	})

	// Each verb runs through productEnv, so a product's replacement reaches every
	// make call and can drop what the default names.
	t.Run("is replaceable", func(t *testing.T) {
		restore := productEnv
		t.Cleanup(func() { productEnv = restore })
		productEnv = func(o Operator) ([]string, error) {
			return []string{utils.Env("REPLACED_VERSION", o.ProductVersion)}, nil
		}

		for _, tc := range verbs() {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeRunner{}
				if err := tc.run(testOperator(), f); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got, _ := envValue(f.calls[0].env, "REPLACED_VERSION"); got != "v3.34.0" {
					t.Errorf("REPLACED_VERSION = %q, want v3.34.0", got)
				}
				for _, dropped := range []string{"CALICO_VERSION", "CALICO_REGISTRY", "CALICO_IMAGE_PATH"} {
					if got, ok := envValue(f.calls[0].env, dropped); ok {
						t.Errorf("%s = %q, want it dropped by the replacement", dropped, got)
					}
				}
			})
		}
	})

	// A branch tag from the manager names no product, and a push does not need one.
	t.Run("skips a missing product registry", func(t *testing.T) {
		for _, tc := range verbs()[1:] {
			t.Run(tc.name, func(t *testing.T) {
				o := testOperator()
				o.ProductRegistry = ""
				f := &fakeRunner{}
				if err := tc.run(o, f); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got, ok := envValue(f.calls[0].env, "CALICO_REGISTRY"); ok {
					t.Errorf("CALICO_REGISTRY = %q, want it unset", got)
				}
				// The product version still goes, whatever the product names it.
				want, err := productEnv(o)
				if err != nil {
					t.Fatalf("productEnv: %v", err)
				}
				if len(want) == 0 {
					t.Error("productEnv dropped the product version along with the registry")
				}
				for _, e := range want {
					if !slices.Contains(f.calls[0].env, e) {
						t.Errorf("env missing %s", e)
					}
				}
			})
		}
	})

	// The operator deploys its own image too, so a build names where it was pushed.
	t.Run("names the operator's own image", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			registries []string
			wantReg    string
			wantPath   string
		}{
			{name: "default", registries: []string{"quay.io/calico"}, wantReg: "quay.io/", wantPath: "calico/"},
			{name: "first of several", registries: []string{"localhost:5000/dev", "quay.io/calico"}, wantReg: "localhost:5000/", wantPath: "dev/"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				o := testOperator()
				o.Registries = tc.registries
				f := &fakeRunner{}
				if err := Build(o, oneVariant(), false, WithRunner(f), WithValidation(false)); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got, _ := envValue(f.calls[0].env, "OPERATOR_IMAGE_REGISTRY"); got != tc.wantReg {
					t.Errorf("OPERATOR_IMAGE_REGISTRY = %q, want %q", got, tc.wantReg)
				}
				if got, _ := envValue(f.calls[0].env, "OPERATOR_IMAGE_PATH"); got != tc.wantPath {
					t.Errorf("OPERATOR_IMAGE_PATH = %q, want %q", got, tc.wantPath)
				}
			})
		}
	})

	// A repeated name is silently last-wins, so a build variable that appears
	// twice would take whichever value came later.
	t.Run("names each variable once", func(t *testing.T) {
		f := &fakeRunner{}
		if err := Build(testOperator(), oneVariant(), false, WithRunner(f), WithValidation(false)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		env, err := productEnv(testOperator())
		if err != nil {
			t.Fatalf("productEnv: %v", err)
		}
		for _, e := range env {
			name, _, ok := strings.Cut(e, "=")
			if !ok {
				t.Errorf("%q is not a name=value pair", e)
				continue
			}
			var seen int
			for _, got := range f.calls[0].env {
				if n, _, _ := strings.Cut(got, "="); n == name {
					seen++
				}
			}
			if seen != 1 {
				t.Errorf("%s appears %d times, want 1", name, seen)
			}
		}
	})

	t.Run("splits a registry", func(t *testing.T) {
		for _, tc := range []struct {
			registry     string
			expRegistry  string
			expImagePath string
			shouldErr    bool
		}{
			{registry: "my-registry/my-namespace", expRegistry: "my-registry/", expImagePath: "my-namespace/"},
			{registry: "my-registry", shouldErr: true},
			{registry: "my-registry/extra/my-namespace", expRegistry: "my-registry/extra/", expImagePath: "my-namespace/"},
			{registry: "my-registry//extra/more/ns/", expRegistry: "my-registry/extra/more/", expImagePath: "ns/"},
		} {
			t.Run(tc.registry, func(t *testing.T) {
				reg, imagePath, err := registryParts(tc.registry)
				if tc.shouldErr {
					if err := err; err == nil {
						t.Fatal("expected an error, got nil")
					}
					return
				}
				if err := err; err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if reg != tc.expRegistry {
					t.Errorf("got %v, want %v", reg, tc.expRegistry)
				}
				if imagePath != tc.expImagePath {
					t.Errorf("got %v, want %v", imagePath, tc.expImagePath)
				}
			})
		}
	})

	t.Run("skips the operator's own image for a bare registry", func(t *testing.T) {
		o := testOperator()
		o.Registries = []string{"localhost:5000"}
		f := &fakeRunner{}
		if err := Publish(o, oneVariant(), false, WithRunner(f)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, ok := envValue(f.calls[0].env, "OPERATOR_IMAGE_REGISTRY"); ok {
			t.Errorf("OPERATOR_IMAGE_REGISTRY = %q, want it unset", got)
		}
	})
}

func TestVerbs(t *testing.T) {
	t.Run("run every variant", func(t *testing.T) {
		variants := []Variant{
			{Name: standardVariant},
			{Name: "alt", Image: "operator-alt", Env: []string{"VARIANT=alt"}},
		}
		f := &fakeRunner{}
		if err := Build(testOperator(), variants, false, WithRunner(f), WithValidation(false)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(f.calls) != 2 {
			t.Fatalf("len = %d, want 2", len(f.calls))
		}

		var got []string
		for _, c := range f.calls {
			v, _ := envValue(c.env, "VARIANT")
			got = append(got, v)
		}
		want := []string{"", "alt"}
		if diff := cmp.Diff(want, got, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
			t.Errorf("variants mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("report every variant's error", func(t *testing.T) {
		f := &fakeRunner{err: fmt.Errorf("boom")}
		variants := []Variant{{Name: standardVariant}, {Name: "alt", Image: "operator-alt"}}
		err := Publish(testOperator(), variants, false, WithRunner(f))

		if err := err; err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), standardVariant) {
			t.Errorf("%q does not contain %q", err.Error(), standardVariant)
		}
		if !strings.Contains(err.Error(), "alt") {
			t.Errorf("%q does not contain %q", err.Error(), "alt")
		}
		if len(f.calls) != 2 {
			t.Fatalf("len = %d, want 2", len(f.calls))
		}
	})

	t.Run("publish records every variant", func(t *testing.T) {
		rec := &fakeRecorder{}
		variants := []Variant{
			{Name: standardVariant},
			{Name: "alt", Image: "operator-alt"},
		}
		o := testOperator()
		o.Registries = []string{"quay.io/a", "quay.io/b"}
		resolve := fakeResolver{
			"quay.io/a/operator:v1.44.0":           "sha256:a",
			"quay.io/a/operator:v1.44.0-arm64":     "sha256:a-arm64",
			"quay.io/b/operator:v1.44.0":           "sha256:b",
			"quay.io/a/operator-alt:v1.44.0":       "sha256:alt",
			"quay.io/b/operator-alt:v1.44.0-arm64": "sha256:alt-arm64",
		}
		err := Publish(o, variants, false, WithRunner(&fakeRunner{}), WithRecord(rec),
			WithResolver(resolve.resolve), WithArches("arm64"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := []string{
			"quay.io/a/operator@sha256:a",
			"quay.io/a/operator@sha256:a-arm64",
			"quay.io/b/operator@sha256:b",
			"quay.io/a/operator-alt@sha256:alt",
			"quay.io/b/operator-alt@sha256:alt-arm64",
		}
		if diff := cmp.Diff(want, rec.refs); diff != "" {
			t.Errorf("refs mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("publish records what a failed push left", func(t *testing.T) {
		rec := &fakeRecorder{}
		resolve := fakeResolver{"quay.io/a/operator:v1.44.0": "sha256:a"}
		err := Publish(oneRegistryOperator(), oneVariant(), false, WithRunner(&fakeRunner{err: fmt.Errorf("boom")}),
			WithRecord(rec), WithResolver(resolve.resolve))
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if diff := cmp.Diff([]string{"quay.io/a/operator@sha256:a"}, rec.refs); diff != "" {
			t.Errorf("refs mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("dry run records nothing", func(t *testing.T) {
		rec := &fakeRecorder{}
		resolve := fakeResolver{"quay.io/a/operator:v1.44.0": "sha256:a"}
		err := Publish(oneRegistryOperator(), oneVariant(), false, WithRunner(&fakeRunner{}), WithDryRun(true),
			WithRecord(rec), WithResolver(resolve.resolve))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rec.refs) != 0 {
			t.Errorf("refs = %v, want none", rec.refs)
		}
	})

	t.Run("validate their configuration", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			o    func(Operator) Operator
			run  func(Operator) error
			want string
		}{
			{
				name: "build needs a product registry",
				o:    func(o Operator) Operator { o.ProductRegistry = ""; return o },
				run: func(o Operator) error {
					return Build(o, oneVariant(), false, WithRunner(&fakeRunner{}), WithValidation(false))
				},
				want: "no product registry specified",
			},
			{
				name: "hashrelease build needs the product version",
				o:    func(o Operator) Operator { o.ProductVersion = ""; return o },
				run: func(o Operator) error {
					return Build(o, oneVariant(), true, WithRunner(&fakeRunner{}), WithValidation(false))
				},
				want: "hashrelease requires the product version",
			},
			{
				name: "build needs a registry",
				o:    func(o Operator) Operator { o.Registries = []string{""}; return o },
				run: func(o Operator) error {
					return Build(o, oneVariant(), false, WithRunner(&fakeRunner{}), WithValidation(false))
				},
				want: "no operator registries specified",
			},
			{
				name: "build needs an operator registry with a path",
				o:    func(o Operator) Operator { o.Registries = []string{"localhost:5000"}; return o },
				run: func(o Operator) error {
					return Build(o, oneVariant(), false, WithRunner(&fakeRunner{}), WithValidation(false))
				},
				want: "operator registry",
			},
			{
				name: "publish needs registries",
				o:    func(o Operator) Operator { o.Registries = nil; return o },
				run:  func(o Operator) error { return Publish(o, oneVariant(), false, WithRunner(&fakeRunner{})) },
				want: "no operator registries specified",
			},
			{
				name: "publish needs a version",
				o:    func(o Operator) Operator { o.Version = ""; return o },
				run:  func(o Operator) error { return Publish(o, oneVariant(), false, WithRunner(&fakeRunner{})) },
				want: "no version specified",
			},
			{
				name: "publish needs a repository root",
				o:    func(o Operator) Operator { o.RepoRoot = ""; return o },
				run:  func(o Operator) error { return Publish(o, oneVariant(), false, WithRunner(&fakeRunner{})) },
				want: "no repository root specified",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.run(tc.o(testOperator()))
				if err := err; err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("%q does not contain %q", err.Error(), tc.want)
				}
			})
		}
	})

	// Without CONFIRM the make targets echo the pushes and exit 0.
	t.Run("publish latches the push", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			opts   []PublishOption
			want   string
			notSet string
		}{
			{name: "confirms by default", want: "CONFIRM", notSet: "DRYRUN"},
			{name: "dry run", opts: []PublishOption{WithDryRun(true)}, want: "DRYRUN", notSet: "CONFIRM"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeRunner{}
				opts := append([]PublishOption{WithRunner(f)}, tc.opts...)
				if err := Publish(testOperator(), oneVariant(), false, opts...); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if len(f.calls) != 1 {
					t.Fatalf("len = %d, want 1", len(f.calls))
				}
				got, ok := envValue(f.calls[0].env, tc.want)
				if !(ok) {
					t.Errorf("expected true")
				}
				if got != "true" {
					t.Errorf("got %v, want %v", got, "true")
				}
				_, set := envValue(f.calls[0].env, tc.notSet)
				if set {
					t.Errorf("expected false")
				}
			})
		}
	})

	t.Run("build marks a release but not a hashrelease", func(t *testing.T) {
		for _, tc := range []struct {
			hashrelease bool
			wantSet     bool
		}{
			{hashrelease: false, wantSet: true},
			{hashrelease: true, wantSet: false},
		} {
			t.Run(fmt.Sprintf("hashrelease=%v", tc.hashrelease), func(t *testing.T) {
				f := &fakeRunner{}
				if err := Build(testOperator(), oneVariant(), tc.hashrelease, WithRunner(f), WithValidation(false)); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				_, set := envValue(f.calls[0].env, "RELEASE")
				if set != tc.wantSet {
					t.Errorf("got %v, want %v", set, tc.wantSet)
				}
			})
		}
	})

	t.Run("publish resumes from its record", func(t *testing.T) {
		variants := []Variant{{Name: standardVariant}, {Name: "alt", Image: "operator-alt"}}
		resolve := fakeResolver{
			"quay.io/a/operator:v1.44.0":     "sha256:a",
			"quay.io/a/operator-alt:v1.44.0": "sha256:alt",
		}

		for _, tc := range []struct {
			name      string
			published []string
			force     bool
			wantRuns  int
			wantErr   string
		}{
			{
				name:      "skips what the record holds",
				published: []string{"quay.io/a/operator@sha256:a"},
				wantRuns:  1,
			},
			{
				name:     "skips nothing without a record",
				wantRuns: 2,
			},
			{
				name:      "refuses a tag that moved",
				published: []string{"quay.io/a/operator@sha256:old", "quay.io/a/operator-alt@sha256:alt"},
				wantErr:   "Pass --force",
			},
			{
				name:      "force publishes a tag that moved",
				published: []string{"quay.io/a/operator@sha256:old", "quay.io/a/operator-alt@sha256:alt"},
				force:     true,
				wantRuns:  1,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeRunner{}
				err := Publish(oneRegistryOperator(), variants, false, WithRunner(f),
					WithResolver(resolve.resolve), WithResume(tc.published, tc.force))
				if tc.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(f.calls) != tc.wantRuns {
					t.Errorf("runs = %d, want %d", len(f.calls), tc.wantRuns)
				}
			})
		}
	})
}

type overlapRunner struct {
	fakeRunner
	running    atomic.Int32
	overlapped atomic.Bool
}

func (f *overlapRunner) RunInDir(_, _ string, args, env []string) (string, error) {
	if f.running.Add(1) > 1 {
		f.overlapped.Store(true)
	}
	defer f.running.Add(-1)
	time.Sleep(20 * time.Millisecond)
	return "", f.record(args, env)
}

func (f *overlapRunner) RunInDirToFile(dir, name string, args, env []string, _ string) (string, error) {
	return f.RunInDir(dir, name, args, env)
}

type fakeResolver map[string]string

func (f fakeResolver) resolve(ref string) (string, bool, error) {
	digest, ok := f[ref]
	return digest, ok, nil
}

type fakeRecorder struct {
	mu   sync.Mutex
	refs []string
}

func (r *fakeRecorder) Add(refs ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs = append(r.refs, refs...)
	return nil
}

func TestPublishBranchTag(t *testing.T) {
	t.Run("retags at the branch", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			version string
			branch  string
			opts    []PublishOption
			wantErr bool
		}{
			{name: "retags at the branch", version: "v1.44.0", branch: "release-v3.33"},
			// The chain retags local images under IMAGETAG, so it needs no version.
			{name: "no version", branch: "release-v3.33"},
			{name: "no branch", version: "v1.44.0", wantErr: true},
			{
				name: "with a recorder", version: "v1.44.0", branch: "release-v3.33",
				opts: []PublishOption{WithRecord(&fakeRecorder{})}, wantErr: true,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				o := testOperator()
				o.Version = tc.version
				f := &fakeRunner{}

				opts := append([]PublishOption{WithRunner(f)}, tc.opts...)
				err := PublishBranchTag(o, oneVariant(), tc.branch, opts...)
				if tc.wantErr {
					if err := err; err == nil {
						t.Fatal("expected an error, got nil")
					}
					if len(f.calls) != 0 {
						t.Errorf("expected empty, got %v", f.calls)
					}
					return
				}
				if err := err; err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(f.calls) != 1 {
					t.Fatalf("len = %d, want 1", len(f.calls))
				}
				got, ok := envValue(f.calls[0].env, utils.EnvImageTag)
				if !(ok) {
					t.Errorf("expected true")
				}
				if got != tc.branch {
					t.Errorf("got %v, want %v", got, tc.branch)
				}
				want := []string{"-C /repo/operator retag-build-images-with-registries push-images-to-registries push-manifests"}
				if diff := cmp.Diff(want, f.targets()); diff != "" {
					t.Errorf("targets mismatch (-want +got):\n%s", diff)
				}
			})
		}
	})

	// No manifest refers to another variant under a branch tag, so the verb drops
	// them whatever the caller passed.
	t.Run("standard variant only", func(t *testing.T) {
		variants := []Variant{
			{Name: standardVariant},
			{Name: "alt", Image: "operator-alt", Env: []string{"VARIANT=alt"}},
		}
		f := &fakeRunner{}
		if err := PublishBranchTag(testOperator(), variants, "release-v3.33", WithRunner(f)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(f.calls) != 1 {
			t.Fatalf("len = %d, want 1", len(f.calls))
		}
		if got, ok := envValue(f.calls[0].env, "VARIANT"); ok {
			t.Errorf("VARIANT = %q, want the standard variant", got)
		}
	})
}

// Build comes first, so a test that cannot build takes verbs()[1:].
func verbs() []struct {
	name string
	run  func(Operator, *fakeRunner) error
} {
	return []struct {
		name string
		run  func(Operator, *fakeRunner) error
	}{
		{name: "build", run: func(o Operator, f *fakeRunner) error {
			return Build(o, oneVariant(), false, WithRunner(f), WithValidation(false))
		}},
		{name: "publish", run: func(o Operator, f *fakeRunner) error {
			return Publish(o, oneVariant(), false, WithRunner(f))
		}},
		{name: "branch tag", run: func(o Operator, f *fakeRunner) error {
			return PublishBranchTag(o, oneVariant(), "release-v3.33", WithRunner(f))
		}},
	}
}
