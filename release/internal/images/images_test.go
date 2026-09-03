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

	"github.com/projectcalico/calico/release/internal/command"
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

// The values every test step is built from. A test names these directly rather
// than through a config object, matching how the verbs are called.
const (
	testRepoRoot = "/repo"
	testVersion  = "v3.30.0"
	testRegistry = "quay.io/tigera"
)

// The options every test step needs: a fake runner and a registry to name
// images in. One helper per step, because the option types differ.
func buildOpts(f command.CommandRunner, extra ...BuildOption) []BuildOption {
	return append([]BuildOption{WithRunner(f), WithRegistries(testRegistry)}, extra...)
}

func archiveOpts(f command.CommandRunner, extra ...ArchiveOption) []ArchiveOption {
	return append([]ArchiveOption{WithRunner(f), WithRegistries(testRegistry)}, extra...)
}

func publishOpts(f command.CommandRunner, extra ...PublishOption) []PublishOption {
	return append([]PublishOption{WithRunner(f), WithRegistries(testRegistry)}, extra...)
}

// publish runs a publish with the usual test settings.
func publish(f command.CommandRunner, variants []Variant, extra ...PublishOption) error {
	return Publish(testRepoRoot, testVersion, variants, true,
		alwaysResolves("sha256:aaa"), publishOpts(f, extra...)...)
}

// A directory shipping several image kinds runs each variant's target, and one
// shipping only some runs only those.
func TestVariantMatrix(t *testing.T) {
	for _, tc := range []struct {
		name        string
		variants    []Variant
		dir         string
		wantTargets []string
	}{
		{"one target per variant", ossVariants(), "node", []string{"release-publish", "release-windows"}},
		{"standard only", ossVariants(), "cmd/calico", []string{"release-publish"}},
		{"shared target, several variants", sharedTargetVariants(), "cmd/calico", []string{"publish-image", "publish-image"}},
		{"dir outside every variant", sharedTargetVariants(), "third_party/dex", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			if err := publish(f, tc.variants); err != nil {
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
	if err := publish(f, sharedTargetVariants()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// The alt variant's env must not leak onto node, which is not an alt dir.
	for _, c := range f.calls {
		if strings.HasSuffix(c.args[1], "node") && hasEnv(c.env, "ALT_VARIANT=true") {
			t.Errorf("alt env leaked onto node: %v", c.env)
		}
	}
}

// Retagging inverts DEV_REGISTRIES: it names the source, so the destination
// has to be given separately.
func TestPublishRetagVersusPush(t *testing.T) {
	t.Run("retag passes the source and the release tag", func(t *testing.T) {
		f := &fakeRunner{}
		err := publish(f, sharedTargetVariants(),
			WithRetag("gcr.io/unique-caldron/hashrelease", "v3.30.0-abcdef", false))
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
		env := f.envFor("cmd/calico", "publish-image")
		for _, want := range []string{
			"IMAGE_ONLY=true",
			"DEV_TAG=v3.30.0-abcdef",
			"DEV_REGISTRIES=gcr.io/unique-caldron/hashrelease",
			"RELEASE_REGISTRIES=" + testRegistry,
			"RELEASE_TAG=" + testVersion,
		} {
			if !hasEnv(env, want) {
				t.Errorf("retag env missing %s, got %v", want, env)
			}
		}
	})

	t.Run("a plain push names no source", func(t *testing.T) {
		f := &fakeRunner{}
		if err := publish(f, sharedTargetVariants()); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if env := f.envFor("cmd/calico", "publish-image"); hasEnv(env, "IMAGE_ONLY=true") {
			t.Errorf("a push should not set IMAGE_ONLY: %v", env)
		}
	})

	t.Run("half a source is an error", func(t *testing.T) {
		f := &fakeRunner{}
		if err := publish(f, ossVariants(), WithRetag("gcr.io/x", "", false)); err == nil {
			t.Error("a retag without a tag should be rejected")
		}
	})
}

// A publish latches CONFIRM; a dry run latches DRYRUN and pushes nothing.
func TestPublishConfirmLatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		confirm bool
		want    string
		notWant string
	}{
		{"confirmed", true, "CONFIRM=true", "DRYRUN=true"},
		{"dry run", false, "DRYRUN=true", "CONFIRM=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			err := Publish(testRepoRoot, testVersion, ossVariants(), tc.confirm,
				alwaysResolves("sha256:aaa"), publishOpts(f)...)
			if err != nil {
				t.Fatalf("Publish: %v", err)
			}
			env := f.envFor("cmd/calico", "release-publish")
			if !hasEnv(env, tc.want) {
				t.Errorf("env missing %s, got %v", tc.want, env)
			}
			if hasEnv(env, tc.notWant) {
				t.Errorf("env should not carry %s, got %v", tc.notWant, env)
			}
		})
	}
}

func TestLogPaths(t *testing.T) {
	t.Run("no logs dir captures in memory", func(t *testing.T) {
		f := &fakeRunner{}
		if err := Build(testRepoRoot, testVersion, ossVariants(), buildOpts(f)...); err != nil {
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
		err := Build(testRepoRoot, testVersion, ossVariants(), buildOpts(f, WithLogsDir("/logs"))...)
		if err != nil {
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

// Scoping the release dirs must scope the work.
func TestScopedVariantPublishesOnlyThoseDirs(t *testing.T) {
	f := &fakeRunner{}
	variants := NarrowVariants(ossVariants(), []string{"node"})
	if err := publish(f, variants); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for _, c := range f.calls {
		if !strings.HasSuffix(c.args[1], "node") {
			t.Errorf("published outside the narrowed dirs: %v", c.args)
		}
	}
}

// Image pushes fail on network flakes, so a unit is retried once.
func TestRetry(t *testing.T) {
	t.Run("one failure is retried", func(t *testing.T) {
		f := &fakeRunner{failures: map[string]int{"/repo/cmd/calico": 1}}
		if err := publish(f, ossVariants()); err != nil {
			t.Fatalf("Publish should recover after one failure: %v", err)
		}
	})

	t.Run("a second failure is reported", func(t *testing.T) {
		f := &fakeRunner{failures: map[string]int{"/repo/cmd/calico": 2}}
		if err := publish(f, ossVariants()); err == nil {
			t.Error("Publish should report a unit that keeps failing")
		}
	})
}

// One component failing must not hide the rest.
func TestPublishCollectsEveryFailure(t *testing.T) {
	f := &fakeRunner{failures: map[string]int{"/repo/node": 9, "/repo/cmd/calico": 9}}
	err := publish(f, ossVariants())
	if err == nil {
		t.Fatal("expected the failures to be reported")
	}
	for _, want := range []string{"node", "cmd/calico"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s, got %q", want, err)
		}
	}
}

// A step cannot run without the values it needs to name an image.
func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		repoRoot string
		version  string
		variants []Variant
	}{
		{"no repo root", "", testVersion, ossVariants()},
		{"no version", testRepoRoot, "", ossVariants()},
		{"no variants", testRepoRoot, testVersion, nil},
		{"variant without a target", testRepoRoot, testVersion,
			[]Variant{{Name: "standard", ReleaseDirs: []string{"node"}}}},
		{"variant without dirs", testRepoRoot, testVersion,
			[]Variant{{Name: "standard", Target: "release-publish"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{}
			err := Publish(tc.repoRoot, tc.version, tc.variants, true, alwaysResolves("sha256:aaa"), publishOpts(f)...)
			if err == nil {
				t.Errorf("Publish should reject %s", tc.name)
			}
		})
	}
}

func TestNarrowVariants(t *testing.T) {
	t.Run("an empty subset leaves the variants alone", func(t *testing.T) {
		got := NarrowVariants(sharedTargetVariants(), nil)
		if len(got) != len(sharedTargetVariants()) {
			t.Errorf("got %d variants, want %d", len(got), len(sharedTargetVariants()))
		}
	})

	t.Run("a subset scopes every variant to it", func(t *testing.T) {
		got := NarrowVariants(sharedTargetVariants(), []string{"whisker"})
		for _, v := range got {
			if !slices.Equal(v.ReleaseDirs, []string{"whisker"}) {
				t.Errorf("variant %s has dirs %v, want [whisker]", v.Name, v.ReleaseDirs)
			}
		}
	})

	t.Run("a variant left with no dirs drops out", func(t *testing.T) {
		got := NarrowVariants(sharedTargetVariants(), []string{"node"})
		for _, v := range got {
			if len(v.ReleaseDirs) == 0 {
				t.Errorf("variant %s kept with no dirs", v.Name)
			}
		}
	})

	// A subset matching nothing yields no work rather than silently running all.
	t.Run("a subset matching nothing yields nothing", func(t *testing.T) {
		if got := NarrowVariants(sharedTargetVariants(), []string{"third_party/dex"}); len(got) != 0 {
			t.Errorf("got %d variants, want none", len(got))
		}
	})
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

// fakeRecorder collects the refs a publish records.
type fakeRecorder struct {
	refs []string
}

func (r *fakeRecorder) Add(refs ...string) error {
	r.refs = append(r.refs, refs...)
	return nil
}

// imageNameRunner answers build-images with a canned image list and
// image-tag-prefix with a prefix, so a test can name images without a checkout.
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

// alwaysResolves answers every image with the same digest. Suitable for asking
// whether anything was recorded, but NOT for anything comparing digests: it
// cannot tell a repo's tags apart. Use resolvesPerTag for that.
func alwaysResolves(digest string) DigestResolver {
	return func(string) (string, bool, error) { return digest, true, nil }
}

// resolvesPerTag gives each tag its own digest, as a registry does, so a repo
// carrying a manifest list and its arch tags holds several distinct digests.
func resolvesPerTag() DigestResolver {
	return func(image string) (string, bool, error) {
		_, tag, _ := strings.Cut(image, ":")
		return "sha256:" + strings.Repeat(fmt.Sprintf("%x", len(tag))[:1], 64), true, nil
	}
}

// recordingOpts are the options a publish needs to record what it pushed.
func recordingOpts(f *imageNameRunner, rec RefRecorder, extra ...PublishOption) []PublishOption {
	return append([]PublishOption{
		WithRunner(f),
		WithRegistries("quay.io/calico"),
		WithArches("amd64", "arm64"),
		WithRecord(rec),
	}, extra...)
}

// oneStandardVariant is a single dir shipping a single image kind.
func oneStandardVariant(dir string) []Variant {
	return []Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{dir}}}
}

// A publish records the manifest list and every per-arch tag: neither digest is
// derivable from the other without asking the registry.
func TestPublishRecordsIndexAndArchRefs(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	rec := &fakeRecorder{}
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("node"), true,
		alwaysResolves("sha256:aaa"), recordingOpts(f, rec)...)
	if err != nil {
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
	err := Publish(testRepoRoot, testVersion,
		[]Variant{{Name: windowsVariant, Target: "release-windows", ReleaseDirs: []string{"node"}}},
		true, alwaysResolves("sha256:bbb"), recordingOpts(f, rec)...)
	if err != nil {
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
	f := &imageNameRunner{images: "node"}
	rec := &fakeRecorder{}
	resolve := func(image string) (string, bool, error) {
		if strings.HasSuffix(image, "-arm64") {
			return "", false, nil
		}
		return "sha256:aaa", true, nil
	}
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("node"), true,
		resolve, recordingOpts(f, rec)...)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(rec.refs) != 2 {
		t.Errorf("expected the absent arm64 tag to be skipped, got %v", rec.refs)
	}
}

// A registry that cannot be reached must not be read as "not published".
func TestPublishFailsOnUnresolvableDigest(t *testing.T) {
	f := &imageNameRunner{images: "node"}
	resolve := func(string) (string, bool, error) {
		return "", false, fmt.Errorf("network is unreachable")
	}
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("node"), true,
		resolve, recordingOpts(f, &fakeRecorder{})...)
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
	f := &imageNameRunner{images: "node"}
	rec := &fakeRecorder{}
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("node"), false,
		alwaysResolves("sha256:aaa"), recordingOpts(f, rec)...)
	if err != nil {
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
	err := Publish(testRepoRoot, testVersion,
		[]Variant{{Name: "alt", Target: "release-publish", Env: []string{"ALT_VARIANT=true"}, ReleaseDirs: []string{"node"}}},
		true, alwaysResolves("sha256:aaa"), recordingOpts(f, rec)...)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
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
	f := &imageNameRunner{images: "node"}
	f.failures = map[string]int{"/repo/whisker": 9}
	rec := &fakeRecorder{}
	err := Publish(testRepoRoot, testVersion,
		[]Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node", "whisker"}}},
		true, alwaysResolves("sha256:aaa"), recordingOpts(f, rec)...)
	if err == nil {
		t.Fatal("expected the failing unit to be reported")
	}
	if len(rec.refs) == 0 {
		t.Error("a partial publish recorded nothing, so a resume cannot tell what landed")
	}
}

// A variant whose Makefile prefixes its tags must publish and record under that
// prefix, not under the unprefixed tag another variant already owns.
func TestPrefixedVariantRecordsPrefixedRefs(t *testing.T) {
	f := &imageNameRunner{images: "calico", prefix: "tesla", envKey: "ALT_VARIANT=true"}
	rec := &fakeRecorder{}
	err := Publish(testRepoRoot, testVersion, []Variant{
		{Name: StandardVariant, Target: "publish-image", ReleaseDirs: []string{"cmd/calico"}},
		{Name: "alt", Target: "publish-image", Env: []string{"ALT_VARIANT=true"}, ReleaseDirs: []string{"cmd/calico"}},
	}, true, alwaysResolves("sha256:abc"), recordingOpts(f, rec)...)
	if err != nil {
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

// Archiving saves every image a variant ships, not a hardcoded pair.
func TestArchiveSavesEveryVariantsImages(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	dir := t.TempDir()
	err := Archive(testRepoRoot, testVersion, []Variant{
		{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}},
		{Name: windowsVariant, Target: "release-windows", ReleaseDirs: []string{"node"}},
	}, dir, archiveOpts(f)...)
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	var saved []string
	for _, c := range f.calls {
		if slices.Contains(c.args, "save") {
			saved = append(saved, c.args[len(c.args)-1])
		}
	}
	slices.Sort(saved)
	want := []string{testRegistry + "/node-windows:" + testVersion, testRegistry + "/node:" + testVersion}
	if !slices.Equal(saved, want) {
		t.Errorf("archived\n got %v\nwant %v", saved, want)
	}
}

// A release that did not build its own images must fetch what is missing.
func TestArchivePullsWhenAsked(t *testing.T) {
	f := &imageNameRunner{images: "node"}
	f.failures = map[string]int{"inspect": 9}
	err := Archive(testRepoRoot, testVersion, oneStandardVariant("node"), t.TempDir(),
		archiveOpts(f, WithPull())...)
	if err != nil {
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
	f := &imageNameRunner{images: "node"}
	if err := Archive(testRepoRoot, testVersion, oneStandardVariant("node"), "", archiveOpts(f)...); err == nil {
		t.Fatal("expected an error when no archive directory is given")
	}
}

// Archiving reads the first registry, so an empty list must be reported rather
// than indexed into.
func TestArchiveRejectsNoRegistry(t *testing.T) {
	f := &imageNameRunner{images: "node"}
	err := Archive(testRepoRoot, testVersion, oneStandardVariant("node"), t.TempDir(), WithRunner(f))
	if err == nil {
		t.Fatal("expected an error when no registry is given")
	}
}

// A unit whose refs are already recorded at the digest the registry serves is
// skipped, so an interrupted release resumes on what is left.
func TestPublishSkipsAlreadyPublishedUnits(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("whisker"), true, alwaysResolves("sha256:aaa"),
		recordingOpts(f, &fakeRecorder{},
			WithResume([]string{"quay.io/calico/whisker@sha256:aaa"}, false))...)
	if err != nil {
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
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("whisker"), true, alwaysResolves("sha256:bbb"),
		recordingOpts(f, &fakeRecorder{},
			WithResume([]string{"quay.io/calico/whisker@sha256:aaa"}, false))...)
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
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("whisker"), true, alwaysResolves("sha256:bbb"),
		recordingOpts(f, &fakeRecorder{},
			WithResume([]string{"quay.io/calico/whisker@sha256:aaa"}, true))...)
	if err != nil {
		t.Fatalf("Publish with force: %v", err)
	}
	var republished bool
	for _, c := range f.calls {
		if slices.Contains(c.args, "release-publish") {
			republished = true
		}
	}
	if !republished {
		t.Error("force did not republish over the mismatch")
	}
}

// A repo publishes several tags at different digests, so a resume must accept
// any digest the record holds for that repo rather than one of them.
func TestResumeAcceptsEveryRecordedDigestForARepo(t *testing.T) {
	variants := oneStandardVariant("node")
	resolve := resolvesPerTag()

	// First run publishes and records the manifest list plus both arch tags.
	f := &imageNameRunner{images: "node"}
	rec := &fakeRecorder{}
	if err := Publish(testRepoRoot, testVersion, variants, true, resolve,
		recordingOpts(f, rec)...); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(rec.refs) < 2 {
		t.Fatalf("expected several refs for one repo, got %v", rec.refs)
	}

	// Resuming against that record must skip, not report a mismatch between
	// two of our own digests.
	f2 := &imageNameRunner{images: "node"}
	err := Publish(testRepoRoot, testVersion, variants, true, resolve,
		recordingOpts(f2, &fakeRecorder{},
			WithResume(rec.refs, false))...)
	if err != nil {
		t.Fatalf("resume of a correct publish failed: %v", err)
	}
	for _, c := range f2.calls {
		if slices.Contains(c.args, "release-publish") {
			t.Error("resume republished an already-recorded unit")
		}
	}
}

// No record means nothing is known to be published, so everything runs and the
// registry is never consulted.
func TestPublishWithoutARecordPublishesEverything(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("whisker"), true,
		alwaysResolves("sha256:aaa"), recordingOpts(f, &fakeRecorder{})...)
	if err != nil {
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

// Step-specific helpers are functions taking settings rather than methods on
// it, so a step cannot reach another step's helper at all. What this once
// checked at run time the package structure now prevents.
