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

package images

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records every make invocation and can fail a component a set number
// of times before succeeding, to exercise the retry.
type fakeRunner struct {
	mu    sync.Mutex
	calls []call
	// failures maps a component directory to how many times it should fail.
	failures map[string]int
}

type call struct {
	args []string
	env  []string
	// logPath is empty when the unit's output was captured in memory.
	logPath string
}

func (f *fakeRunner) RunInDir(_, _ string, args, env []string) (string, error) {
	return f.record(args, env, "")
}

func (f *fakeRunner) RunInDirToFile(_, _ string, args, env []string, logPath string) (string, error) {
	return f.record(args, env, logPath)
}

func (f *fakeRunner) record(args, env []string, logPath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{args: slices.Clone(args), env: slices.Clone(env), logPath: logPath})
	dir := args[1]
	if n, ok := f.failures[dir]; ok && n > 0 {
		f.failures[dir] = n - 1
		return "boom", fmt.Errorf("push failed")
	}
	return "ok", nil
}

// Run records too: archiving drives docker through it rather than make.
func (f *fakeRunner) Run(_ string, args, env []string) (string, error) {
	return f.record(args, env, "")
}

func (f *fakeRunner) RunNoCapture(string, []string, []string) error              { return nil }
func (f *fakeRunner) RunInDirNoCapture(string, string, []string, []string) error { return nil }

// targetsFor returns the make targets invoked for a component directory.
func (f *fakeRunner) targetsFor(dir string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasSuffix(c.args[1], dir) {
			out = append(out, c.args[2:]...)
		}
	}
	return out
}

// envFor returns the environment of the first call for a component and target.
func (f *fakeRunner) envFor(dir, target string) []string {
	for _, c := range f.calls {
		if strings.HasSuffix(c.args[1], dir) && slices.Contains(c.args[2:], target) {
			return c.env
		}
	}
	return nil
}

func hasEnv(env []string, want string) bool {
	return slices.Contains(env, want)
}

func hasEnvPrefix(env []string, prefix string) bool {
	return slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, prefix) })
}

// ossVariants mirrors the OSS publish shape: windows is a separate target.
func ossVariants() []Variant {
	return []Variant{
		{Name: "standard", Target: "release-publish", ReleaseDirs: []string{"cmd/calico", "node"}},
		{Name: "windows", Target: "release-windows", ReleaseDirs: []string{"node"}},
	}
}

// sharedTargetVariants covers the other way a target tells variants apart: one
// target for all of them, with environment selecting which image is published.
func sharedTargetVariants() []Variant {
	return []Variant{
		{Name: "standard", Target: "publish-image", ReleaseDirs: []string{"cmd/calico", "whisker", "node"}},
		{Name: "alt", Target: "publish-image", Env: []string{"ALT_VARIANT=true"}, ReleaseDirs: []string{"cmd/calico", "whisker"}},
		{Name: "windows", Target: "publish-image", Env: []string{"WINDOWS=true"}, ReleaseDirs: []string{"node"}},
	}
}

func baseConfig(f *fakeRunner, variants []Variant) Config {
	return Config{
		RepoRoot:   "/repo",
		Version:    "v3.30.0",
		Registries: []string{"quay.io/tigera"},
		Variants:   variants,
	}.apply([]Option{WithRunner(f)})
}

func TestVariantMatrix(t *testing.T) {
	tests := []struct {
		name        string
		variants    []Variant
		dir         string
		wantTargets []string
		wantEnv     []string
		notEnv      []string
	}{
		{
			name:        "OSS dir in standard only",
			variants:    ossVariants(),
			dir:         "cmd/calico",
			wantTargets: []string{"release-publish"},
		},
		{
			name:        "OSS dir in standard and windows gets both targets",
			variants:    ossVariants(),
			dir:         "node",
			wantTargets: []string{"release-publish", "release-windows"},
		},
		{
			name:        "dir in standard and cloud gets the target twice",
			variants:    sharedTargetVariants(),
			dir:         "whisker",
			wantTargets: []string{"publish-image", "publish-image"},
		},
		{
			name:        "dir outside every variant",
			variants:    sharedTargetVariants(),
			dir:         "third_party/dex",
			wantTargets: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			p, err := NewPublisher(baseConfig(f, tc.variants))
			if err != nil {
				t.Fatalf("NewPublisher: %v", err)
			}
			if err := p.Publish(); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			got := f.targetsFor(tc.dir)
			slices.Sort(got)
			want := slices.Clone(tc.wantTargets)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("targets for %s = %v, want %v", tc.dir, got, want)
			}
		})
	}
}

// A variant's env reaches only its own units, never a sibling variant's.
func TestVariantEnvIsScopedToItsVariant(t *testing.T) {
	f := &fakeRunner{}
	p, err := NewPublisher(baseConfig(f, sharedTargetVariants()))
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// node is in standard and windows; exactly one of its calls carries the
	// windows env.
	var windows, plain int
	for _, c := range f.calls {
		if !strings.HasSuffix(c.args[1], "node") {
			continue
		}
		if hasEnv(c.env, "WINDOWS=true") {
			windows++
		} else {
			plain++
		}
	}
	if windows != 1 || plain != 1 {
		t.Errorf("node calls: %d windows, %d plain; want 1 and 1", windows, plain)
	}

	// The cloud variant's env must not leak onto node, which is not a cloud dir.
	for _, c := range f.calls {
		if strings.HasSuffix(c.args[1], "node") && hasEnv(c.env, "ALT_VARIANT=true") {
			t.Error("cloud env leaked onto a non-cloud component")
		}
	}
}

func TestPublishRetagVersusPush(t *testing.T) {
	t.Run("retag passes the source and the release tag", func(t *testing.T) {
		f := &fakeRunner{}
		cfg := baseConfig(f, sharedTargetVariants())
		cfg.From = "gcr.io/unique-caldron/hashrelease"
		cfg.FromTag = "v3.30.0-abcdef"
		p, err := NewPublisher(cfg)
		if err != nil {
			t.Fatalf("NewPublisher: %v", err)
		}
		if err := p.Publish(); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		env := f.envFor("cmd/calico", "publish-image")
		for _, want := range []string{
			"DEV_TAG=v3.30.0-abcdef",
			"DEV_REGISTRIES=gcr.io/unique-caldron/hashrelease",
			// The retag destination. Unset, the Makefile silently falls back to
			// its own default registry.
			"RELEASE_REGISTRIES=quay.io/tigera",
			"RELEASE_TAG=v3.30.0",
			"IMAGE_ONLY=true",
		} {
			if !hasEnv(env, want) {
				t.Errorf("retag env missing %s", want)
			}
		}
	})

	t.Run("push passes none of the retag settings", func(t *testing.T) {
		f := &fakeRunner{}
		p, err := NewPublisher(baseConfig(f, ossVariants()))
		if err != nil {
			t.Fatalf("NewPublisher: %v", err)
		}
		if err := p.Publish(); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		env := f.envFor("cmd/calico", "release-publish")
		for _, unwanted := range []string{"DEV_TAG=", "RELEASE_TAG=", "IMAGE_ONLY=", "RELEASE_REGISTRIES="} {
			if hasEnvPrefix(env, unwanted) {
				t.Errorf("push env should not carry %s", unwanted)
			}
		}
		if !hasEnv(env, "DEV_REGISTRIES=quay.io/tigera") {
			t.Error("push env should send DEV_REGISTRIES to the product registries")
		}
	})
}

// A real publish must latch CONFIRM; a dry run must latch DRYRUN. Getting this
// backwards either publishes a rehearsal or silently publishes nothing.
func TestPublishConfirmLatch(t *testing.T) {
	for _, tc := range []struct {
		name          string
		publish       bool
		want, notWant string
	}{
		{"publishing confirms", true, "CONFIRM=true", "DRYRUN=true"},
		{"not publishing dry runs", false, "DRYRUN=true", "CONFIRM=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			cfg := baseConfig(f, ossVariants())
			cfg.Publish = tc.publish
			p, err := NewPublisher(cfg)
			if err != nil {
				t.Fatalf("NewPublisher: %v", err)
			}
			if err := p.Publish(); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			env := f.envFor("cmd/calico", "release-publish")
			if !hasEnv(env, tc.want) {
				t.Errorf("env missing %s", tc.want)
			}
			if hasEnv(env, tc.notWant) {
				t.Errorf("env should not carry %s", tc.notWant)
			}
		})
	}
}

func TestLogPaths(t *testing.T) {
	t.Run("no logs dir captures in memory", func(t *testing.T) {
		f := &fakeRunner{}
		if err := Build(baseConfig(f, ossVariants())); err != nil {
			t.Fatalf("Build: %v", err)
		}
		for _, c := range f.calls {
			if c.logPath != "" {
				t.Errorf("unexpected log file %s", c.logPath)
			}
		}
	})

	// A component shipping two image kinds must not have one log overwrite the
	// other, so the variant is part of the file name.
	t.Run("each variant logs to its own file", func(t *testing.T) {
		f := &fakeRunner{}
		cfg := baseConfig(f, ossVariants())
		cfg.LogsDir = "/logs"
		if err := Build(cfg); err != nil {
			t.Fatalf("Build: %v", err)
		}
		var got []string
		for _, c := range f.calls {
			got = append(got, c.logPath)
		}
		slices.Sort(got)
		want := []string{
			"/logs/images-build/cmd-calico.log",
			"/logs/images-build/node-windows.log",
			"/logs/images-build/node.log",
		}
		if !slices.Equal(got, want) {
			t.Errorf("log paths\n got %v\nwant %v", got, want)
		}
	})
}

// Scoping the release dirs must scope the work: publish once read the full list
// while prep read the narrowed one.
func TestScopedVariantPublishesOnlyThoseDirs(t *testing.T) {
	f := &fakeRunner{}
	cfg := baseConfig(f, []Variant{
		{Name: "standard", Target: "publish-image", ReleaseDirs: []string{"whisker"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(f.calls))
	}
	if !strings.HasSuffix(f.calls[0].args[1], "whisker") {
		t.Errorf("published %s, want whisker", f.calls[0].args[1])
	}
}

func TestRetry(t *testing.T) {
	t.Run("one failure then success", func(t *testing.T) {
		f := &fakeRunner{failures: map[string]int{"/repo/whisker": 1}}
		cfg := baseConfig(f, []Variant{
			{Name: "standard", Target: "publish-image", ReleaseDirs: []string{"whisker"}},
		})
		p, _ := NewPublisher(cfg)
		if err := p.Publish(); err != nil {
			t.Errorf("Publish should recover after one failure: %v", err)
		}
		if len(f.calls) != 2 {
			t.Errorf("got %d attempts, want 2", len(f.calls))
		}
	})

	t.Run("two failures fail", func(t *testing.T) {
		f := &fakeRunner{failures: map[string]int{"/repo/whisker": 2}}
		cfg := baseConfig(f, []Variant{
			{Name: "standard", Target: "publish-image", ReleaseDirs: []string{"whisker"}},
		})
		p, _ := NewPublisher(cfg)
		if err := p.Publish(); err == nil {
			t.Error("Publish should fail after exhausting retries")
		}
	})
}

// One component failing must not hide the others' failures.
func TestPublishCollectsEveryFailure(t *testing.T) {
	f := &fakeRunner{failures: map[string]int{"/repo/whisker": 9, "/repo/node": 9}}
	cfg := baseConfig(f, []Variant{
		{Name: "standard", Target: "publish-image", ReleaseDirs: []string{"whisker", "node", "cmd/calico"}},
	})
	p, _ := NewPublisher(cfg)
	err := p.Publish()
	if err == nil {
		t.Fatal("Publish should fail")
	}
	for _, want := range []string{"whisker", "node"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s: %v", want, err)
		}
	}
}

func TestBuildRejectsPublishSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"From", func(c *Config) { c.From = "gcr.io/x"; c.FromTag = "v1" }},
		{"Scan", func(c *Config) { c.Scan = &ScanRequest{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig(&fakeRunner{}, ossVariants())
			tc.mut(&cfg)
			if err := Build(cfg); err == nil {
				t.Errorf("Build should reject %s", tc.name)
			}
		})
	}
}

func TestNewPublisherRejectsHalfSetSource(t *testing.T) {
	cfg := baseConfig(&fakeRunner{}, ossVariants())
	cfg.From = "gcr.io/x"
	if _, err := NewPublisher(cfg); err == nil {
		t.Error("NewPublisher should reject From without FromTag")
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"no repo root", func(c *Config) { c.RepoRoot = "" }},
		{"no version", func(c *Config) { c.Version = "" }},
		{"no variants", func(c *Config) { c.Variants = nil }},
		{"variant without a target", func(c *Config) { c.Variants[0].Target = "" }},
		{"variant without dirs", func(c *Config) { c.Variants[0].ReleaseDirs = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig(&fakeRunner{}, ossVariants())
			tc.mut(&cfg)
			if _, err := NewPublisher(cfg); err == nil {
				t.Errorf("expected %s to be rejected", tc.name)
			}
		})
	}
}

// Narrowing a run must narrow every variant, not just the standard one: the
// manager's publish path used to read the full list while prep read the
// narrowed one.
func TestNarrowVariants(t *testing.T) {
	t.Run("empty subset leaves variants untouched", func(t *testing.T) {
		got := NarrowVariants(sharedTargetVariants(), nil)
		if len(got) != 3 {
			t.Fatalf("got %d variants, want 3", len(got))
		}
	})

	t.Run("subset narrows every variant", func(t *testing.T) {
		got := NarrowVariants(sharedTargetVariants(), []string{"whisker"})
		if len(got) != 2 {
			t.Fatalf("got %d variants, want standard and cloud", len(got))
		}
		for _, v := range got {
			if !slices.Equal(v.ReleaseDirs, []string{"whisker"}) {
				t.Errorf("variant %s has dirs %v, want [whisker]", v.Name, v.ReleaseDirs)
			}
		}
	})

	// node is in standard and windows but not cloud, so cloud drops out.
	t.Run("a variant with no overlap is dropped", func(t *testing.T) {
		got := NarrowVariants(sharedTargetVariants(), []string{"node"})
		var names []string
		for _, v := range got {
			names = append(names, v.Name)
		}
		if !slices.Equal(names, []string{"standard", "windows"}) {
			t.Fatalf("got %v, want standard and windows", names)
		}
	})

	// A subset matching nothing yields no work rather than silently running all.
	t.Run("a subset matching nothing drops every variant", func(t *testing.T) {
		if got := NarrowVariants(sharedTargetVariants(), []string{"third_party/dex"}); len(got) != 0 {
			t.Fatalf("got %v, want none", got)
		}
	})
}

// fakeRecorder collects the refs a publish records.
type fakeRecorder struct {
	refs []string
}

func (r *fakeRecorder) Add(refs ...string) error {
	r.refs = append(r.refs, refs...)
	return nil
}

// imageNameRunner answers build-images with a canned image list and every
// other call with success.
type imageNameRunner struct {
	fakeRunner
	images string
	// prefix is echoed for image-tag-prefix only when the call carries envKey,
	// mimicking a Makefile that sets IMAGETAG_PREFIX from a variant's env.
	prefix string
	envKey string
}

func (r *imageNameRunner) RunInDir(_, _ string, args, env []string) (string, error) {
	if _, err := r.record(args, env, ""); err != nil {
		return "", err
	}
	if slices.Contains(args, "build-images") {
		return r.images, nil
	}
	if slices.Contains(args, "image-tag-prefix") {
		if r.envKey == "" || slices.Contains(env, r.envKey) {
			return r.prefix, nil
		}
		return "", nil
	}
	return "", nil
}

func recordingConfig(f *imageNameRunner, rec RefRecorder, resolve DigestResolver, variants []Variant) Config {
	return Config{
		RepoRoot:      "/repo",
		Version:       "v3.30.0",
		Registries:    []string{"quay.io/calico"},
		Arches:        []string{"amd64", "arm64"},
		Variants:      variants,
		Publish:       true,
		Refs:          rec,
		ResolveDigest: resolve,
	}.apply([]Option{WithRunner(f)})
}

func alwaysResolves(digest string) DigestResolver {
	return func(string) (string, bool, error) { return digest, true, nil }
}

// A publish records the manifest list and every per-arch tag: neither digest is
// derivable from the other without asking the registry.
func TestPublishRecordsIndexAndArchRefs(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:aaa"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// One manifest list plus one tag per architecture.
	if len(rec.refs) != 3 {
		t.Fatalf("expected 3 refs (index + 2 arches), got %v", rec.refs)
	}
	for _, ref := range rec.refs {
		if ref != "quay.io/calico/node@sha256:aaa" {
			t.Errorf("unexpected ref %s", ref)
		}
	}
}

// The windows variant copies only its manifest list to the release tag, so it
// has no per-arch tags to record.
func TestPublishRecordsWindowsIndexOnly(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:bbb"), []Variant{
		{Name: "windows", Target: "release-windows", ReleaseDirs: []string{"node"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	want := []string{"quay.io/calico/node-windows@sha256:bbb"}
	if !slices.Equal(rec.refs, want) {
		t.Errorf("refs\n got %v\nwant %v", rec.refs, want)
	}
}

// A tag the publish did not produce is skipped, not recorded and not an error:
// the manifest and architecture halves are separately skippable.
func TestPublishSkipsAbsentTags(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	rec := &fakeRecorder{}
	resolve := func(image string) (string, bool, error) {
		if strings.HasSuffix(image, "-arm64") {
			return "", false, nil
		}
		return "sha256:aaa", true, nil
	}
	cfg := recordingConfig(f, rec, resolve, []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(rec.refs) != 2 {
		t.Errorf("expected the absent arm64 tag to be skipped, got %v", rec.refs)
	}
}

// A registry that cannot be reached must not be read as "not published".
func TestPublishFailsOnUnresolvableDigest(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	resolve := func(string) (string, bool, error) {
		return "", false, fmt.Errorf("network is unreachable")
	}
	cfg := recordingConfig(f, &fakeRecorder{}, resolve, []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	err = p.Publish()
	if err == nil {
		t.Fatal("expected an error when a digest cannot be resolved")
	}
	if !strings.Contains(err.Error(), "network is unreachable") {
		t.Errorf("error should carry the cause, got %q", err)
	}
}

// A dry run publishes nothing, so it must record nothing: a record of images
// that do not exist would mislead the run that resumes from it.
func TestDryRunRecordsNothing(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:aaa"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
	})
	// Refs stays set: dropping it is the publisher's job, not the caller's.
	cfg.Publish = false
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(rec.refs) != 0 {
		t.Errorf("a dry run recorded refs: %v", rec.refs)
	}
}

// A variant that is neither standard nor windows must publish the unsuffixed
// images and keep its per-architecture tags. Testing "not standard" instead of
// "is windows" gets both wrong.
func TestThirdVariantIsNotTreatedAsWindows(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:aaa"), []Variant{
		{Name: "alt", Target: "release-publish", Env: []string{"ALT_VARIANT=true"}, ReleaseDirs: []string{"node"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// The manifest list plus one tag per architecture, all for the unsuffixed
	// image; a Windows unit would record one ref for node-windows.
	if len(rec.refs) != 3 {
		t.Fatalf("expected 3 refs (index + 2 arches), got %v", rec.refs)
	}
	for _, ref := range rec.refs {
		if strings.Contains(ref, windowsImageSuffix) {
			t.Errorf("a non-Windows variant recorded a Windows image: %s", ref)
		}
	}
}

// A partial publish must still record what reached the registry: that record is
// what a resumed run reads to decide the work left.
func TestPublishRecordsWhatSucceededWhenAUnitFails(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	f.failures = map[string]int{"/repo/whisker": 9}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:aaa"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node", "whisker"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err == nil {
		t.Fatal("expected the failing unit to be reported")
	}
	if len(rec.refs) == 0 {
		t.Error("a partial publish recorded nothing, so a resume cannot tell what landed")
	}
}

// The release tarball ships the standard images only; the Windows images have
// an archive of their own.
func TestStandardVariantsDropsOtherKinds(t *testing.T) {
	got := StandardVariants(PublishVariants)
	if len(got) != 1 {
		t.Fatalf("expected only the standard variant, got %d", len(got))
	}
	if got[0].Name != StandardVariant {
		t.Errorf("kept %q, want %q", got[0].Name, StandardVariant)
	}
}

// Archiving saves every image a variant ships, not a hardcoded pair.
func TestArchiveSavesEveryVariantsImages(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	dir := t.TempDir()
	cfg := baseConfig(&f.fakeRunner, []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
		{Name: windowsVariant, Target: "release-windows", ReleaseDirs: []string{"node"}},
	})
	if err := Archive(cfg, dir, false, WithRunner(f)); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	var saved []string
	for _, c := range f.calls {
		if slices.Contains(c.args, "save") {
			saved = append(saved, c.args[len(c.args)-1])
		}
	}
	slices.Sort(saved)
	want := []string{"quay.io/tigera/node-windows:v3.30.0", "quay.io/tigera/node:v3.30.0"}
	if !slices.Equal(saved, want) {
		t.Errorf("archived\n got %v\nwant %v", saved, want)
	}
}

// A release that did not build its own images must fetch what is missing.
func TestArchivePullsWhenAsked(t *testing.T) {
	f := &imageNameRunner{images: "node"}
	f.failures = map[string]int{"inspect": 9}
	cfg := baseConfig(&f.fakeRunner, []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
	})
	if err := Archive(cfg, t.TempDir(), true, WithRunner(f)); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	var pulled bool
	for _, c := range f.calls {
		if slices.Contains(c.args, "pull") {
			pulled = true
		}
	}
	if !pulled {
		t.Error("a missing image was not pulled before saving")
	}
}

func TestArchiveRejectsNoDir(t *testing.T) {
	cfg := baseConfig(&fakeRunner{}, []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
	})
	if err := Archive(cfg, "", false); err == nil {
		t.Fatal("expected an error when no archive directory is given")
	}
}

// A variant whose Makefile prefixes its tags must publish and record under that
// prefix, not under the unprefixed tag another variant already owns.
func TestPrefixedVariantRecordsPrefixedRefs(t *testing.T) {
	f := &imageNameRunner{images: "calico", prefix: "tesla", envKey: "ALT_VARIANT=true"}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:abc"), []Variant{
		{Name: StandardVariant, Target: "publish-image", ReleaseDirs: []string{"cmd/calico"}},
		{Name: "alt", Target: "publish-image", Env: []string{"ALT_VARIANT=true"}, ReleaseDirs: []string{"cmd/calico"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var prefixed, bare int
	for _, c := range f.calls {
		if !slices.Contains(c.args, "image-tag-prefix") {
			continue
		}
		if hasEnv(c.env, "ALT_VARIANT=true") {
			prefixed++
		} else {
			bare++
		}
	}
	if prefixed != 1 || bare != 1 {
		t.Errorf("tag-prefix lookups: %d with the variant env, %d without; want 1 and 1", prefixed, bare)
	}
	if len(rec.refs) == 0 {
		t.Fatal("nothing recorded")
	}
}

// A unit whose refs are already recorded at the digest the registry serves is
// skipped, so an interrupted release resumes on what is left.
func TestPublishSkipsAlreadyPublishedUnits(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	rec := &fakeRecorder{}
	cfg := recordingConfig(f, rec, alwaysResolves("sha256:aaa"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"whisker"}},
	})
	cfg.Published = []string{"quay.io/calico/whisker@sha256:aaa"}
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for _, c := range f.calls {
		if slices.Contains(c.args, "release-publish") {
			t.Errorf("republished an already-published unit: %v", c.args)
		}
	}
}

// A tag serving a digest the record does not know is an error: something moved
// it, and republishing over it silently would ship the wrong image.
func TestPublishFailsOnDigestMismatch(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	cfg := recordingConfig(f, &fakeRecorder{}, alwaysResolves("sha256:bbb"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"whisker"}},
	})
	cfg.Published = []string{"quay.io/calico/whisker@sha256:aaa"}
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	err = p.Publish()
	if err == nil {
		t.Fatal("expected a mismatch to be reported")
	}
	// The message has to be actionable at 2am mid-release: what is published,
	// what this release recorded, and how to override.
	for _, want := range []string{"sha256:aaa", "sha256:bbb", "whisker", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got %q", want, err)
		}
	}
}

// --force republishes over a mismatch rather than failing.
func TestPublishForceOverridesMismatch(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	cfg := recordingConfig(f, &fakeRecorder{}, alwaysResolves("sha256:bbb"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"whisker"}},
	})
	cfg.Published = []string{"quay.io/calico/whisker@sha256:aaa"}
	cfg.Force = true
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish with --force: %v", err)
	}
	var republished bool
	for _, c := range f.calls {
		if slices.Contains(c.args, "release-publish") {
			republished = true
		}
	}
	if !republished {
		t.Error("--force did not republish over the mismatch")
	}
}

// An empty record means nothing is known, so everything publishes.
func TestPublishWithoutARecordPublishesEverything(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	cfg := recordingConfig(f, &fakeRecorder{}, alwaysResolves("sha256:aaa"), []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"whisker"}},
	})
	p, err := NewPublisher(cfg)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := p.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	var published bool
	for _, c := range f.calls {
		if slices.Contains(c.args, "release-publish") {
			published = true
		}
	}
	if !published {
		t.Error("a run with no record published nothing")
	}
}
