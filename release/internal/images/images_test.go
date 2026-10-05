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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/steps"
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
	// dir is where the command was run.
	dir  string
	args []string
	env  []string
	// logPath is empty when the unit's output was captured in memory.
	logPath string
}

func (f *fakeRunner) RunInDir(dir, _ string, args, env []string) (string, error) {
	return f.record(dir, args, env, "")
}

func (f *fakeRunner) RunInDirToFile(dir, _ string, args, env []string, logPath string) (string, error) {
	return f.record(dir, args, env, logPath)
}

func (f *fakeRunner) record(runDir string, args, env []string, logPath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{dir: runDir, args: slices.Clone(args), env: slices.Clone(env), logPath: logPath})
	dir := args[1]
	if n, ok := f.failures[dir]; ok && n > 0 {
		f.failures[dir] = n - 1
		return "boom", fmt.Errorf("push failed")
	}
	return "ok", nil
}

// Run records too: archiving drives docker through it rather than make.
func (f *fakeRunner) Run(_ string, args, env []string) (string, error) {
	return f.record("", args, env, "")
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

func TestPublishEnv(t *testing.T) {
	t.Run("is replaceable", func(t *testing.T) {
		restore := publishEnv
		t.Cleanup(func() { publishEnv = restore })
		publishEnv = func(s settings) []string {
			return append(slices.DeleteFunc(restore(s), func(e string) bool {
				return strings.HasPrefix(e, "RELEASE=")
			}), "REPLACED=true")
		}

		for _, tc := range []struct {
			name  string
			extra []PublishOption
		}{
			{name: "push"},
			{name: "retag", extra: []PublishOption{WithRetag("gcr.io/unique-caldron/hashrelease", "v3.30.0-abcdef", false)}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeRunner{}
				if err := publish(f, sharedTargetVariants(), tc.extra...); err != nil {
					t.Fatalf("Publish: %v", err)
				}
				env := f.envFor("cmd/calico", "publish-image")
				if !hasEnv(env, "REPLACED=true") {
					t.Errorf("env missing the added variable, got %v", env)
				}
				if hasEnv(env, "RELEASE=true") {
					t.Errorf("env still carries the dropped RELEASE, got %v", env)
				}
			})
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

	t.Run("reports every invalid input at once", func(t *testing.T) {
		declared := []Variant{
			{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}, Images: []string{"whisker"}},
			{Name: "alt", Target: "release-publish", ReleaseDirs: []string{"node"}, Images: []string{"whisker"}},
		}
		err := Publish("", testVersion, declared, true, alwaysResolves("sha256:aaa"), recordingOpts(&imageNameRunner{}, &fakeRecorder{})...)
		for _, want := range []string{"no repository root", `variant "standard" declares`, `variant "alt" declares`} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("got %v, want it to contain %q", err, want)
			}
		}
	})

	t.Run("other steps reject declared images", func(t *testing.T) {
		declared := []Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}, Images: []string{"whisker"}}}
		f := &imageNameRunner{images: "node"}
		err := Publish(testRepoRoot, testVersion, declared, true, alwaysResolves("sha256:aaa"), recordingOpts(f, &fakeRecorder{})...)
		if err == nil || !strings.Contains(err.Error(), "declares its images") {
			t.Errorf("expected a publish of declared images to fail, got %v", err)
		}
		if slices.Contains(f.targetsFor("node"), "release-publish") {
			t.Error("the publish ran its target anyway")
		}
	})
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
	// perDir names each image after its own directory, so a test can tell the
	// units' results apart.
	perDir bool
}

// dirArg returns the directory a make invocation was pointed at.
func dirArg(args []string) string {
	for i, a := range args {
		if a == "-C" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (r *imageNameRunner) RunInDir(dir, _ string, args, env []string) (string, error) {
	if _, err := r.record(dir, args, env, ""); err != nil {
		return "", err
	}
	if slices.Contains(args, "build-images") {
		if r.perDir {
			return path.Base(dirArg(args)), nil
		}
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
func alwaysResolves(digest string) steps.DigestResolver {
	return func(string) (string, bool, error) { return digest, true, nil }
}

// resolvesPerTag gives each tag its own digest, as a registry does, so a repo
// carrying a manifest list and its arch tags holds several distinct digests.
func resolvesPerTag() steps.DigestResolver {
	return func(image string) (string, bool, error) {
		_, tag, _ := strings.Cut(image, ":")
		return "sha256:" + strings.Repeat(fmt.Sprintf("%x", len(tag))[:1], 64), true, nil
	}
}

// recordingOpts are the options a publish needs to record what it pushed.
func recordingOpts(f *imageNameRunner, rec steps.RefRecorder, extra ...PublishOption) []PublishOption {
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
		[]Variant{{Name: WindowsVariant, Target: "release-windows", ReleaseDirs: []string{"node"}}},
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

// The tarball ships what a user deploys: standard images only, since the
// Windows images have an archive of their own.
func TestArchiveSavesStandardImagesOnly(t *testing.T) {
	f := &imageNameRunner{images: "node node-windows"}
	dir := t.TempDir()
	if err := Archive(testRepoRoot, testVersion, []string{"node"}, archiveOpts(f)...).Contribute(dir); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	var saved []string
	for _, c := range f.calls {
		if slices.Contains(c.args, "save") {
			saved = append(saved, c.args[len(c.args)-1])
		}
	}
	slices.Sort(saved)
	want := []string{testRegistry + "/node:" + testVersion}
	if !slices.Equal(saved, want) {
		t.Errorf("archived\n got %v\nwant %v", saved, want)
	}
}

// A release that did not build its own images must fetch what is missing.
func TestArchivePullsWhenAsked(t *testing.T) {
	f := &imageNameRunner{images: "node"}
	f.failures = map[string]int{"inspect": 9}
	if err := Archive(testRepoRoot, testVersion, []string{"node"}, archiveOpts(f, WithPull(true))...).Contribute(t.TempDir()); err != nil {
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
	if err := Archive(testRepoRoot, testVersion, []string{"node"}, archiveOpts(f)...).Contribute(""); err == nil {
		t.Fatal("expected an error when no archive directory is given")
	}
}

// Archiving reads the first registry, so an empty list must be reported rather
// than indexed into.
func TestArchiveRejectsNoRegistry(t *testing.T) {
	f := &imageNameRunner{images: "node"}
	err := Archive(testRepoRoot, testVersion, []string{"node"}, WithRunner(f)).Contribute(t.TempDir())
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

// A lookup that fails reaches no verdict, so the unit is published rather than
// aborting a resume that a flaky registry would otherwise stop.
func TestPublishOnUnresolvableDigest(t *testing.T) {
	f := &imageNameRunner{images: "whisker"}
	resolve := func(string) (string, bool, error) {
		return "", false, errors.New("unauthorized")
	}
	// Recording resolves the digests it just pushed and is a separate concern,
	// so this drives the resume decision alone.
	err := Publish(testRepoRoot, testVersion, oneStandardVariant("whisker"), true, resolve,
		WithRunner(f), WithRegistries("quay.io/calico"),
		WithResume([]string{"quay.io/calico/whisker@sha256:aaa"}, false))
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
		t.Errorf("a failed lookup skipped the unit instead of publishing it: %v", f.calls)
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

// The lookups run concurrently, so the record must still come back in the
// units' order: a reader diffing two runs' records compares them line by line.
func TestPublishRecordsInUnitOrder(t *testing.T) {
	dirs := []string{"node", "whisker", "cmd/calico", "istio"}
	f := &imageNameRunner{perDir: true}
	rec := &fakeRecorder{}
	if err := Publish(testRepoRoot, testVersion,
		[]Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: dirs}},
		true, resolvesPerTag(), recordingOpts(f, rec)...); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Each unit names its image after its own directory, so the record's refs
	// must first mention the directories in the order the units were given.
	var seen []string
	for _, ref := range rec.refs {
		name := path.Base(strings.SplitN(ref, "@", 2)[0])
		if len(seen) == 0 || seen[len(seen)-1] != name {
			seen = append(seen, name)
		}
	}
	want := []string{"node", "whisker", "calico", "istio"}
	if !slices.Equal(seen, want) {
		t.Errorf("record out of order:\n got %v\nwant %v", seen, want)
	}
}

// A skipped unit must not shift the ones left to publish: pending resolves the
// units concurrently and has to put the survivors back in order.
func TestResumeKeepsPendingUnitsInOrder(t *testing.T) {
	dirs := []string{"node", "whisker", "cmd/calico", "istio"}
	variants := []Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: dirs}}
	resolve := resolvesPerTag()

	// Seed a record covering only whisker, so the other three are still owed.
	seed := &fakeRecorder{}
	if err := Publish(testRepoRoot, testVersion,
		[]Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"whisker"}}},
		true, resolve, recordingOpts(&imageNameRunner{perDir: true}, seed)...); err != nil {
		t.Fatalf("seeding publish: %v", err)
	}

	f := &imageNameRunner{perDir: true}
	if err := Publish(testRepoRoot, testVersion, variants, true, resolve,
		recordingOpts(f, &fakeRecorder{}, WithResume(seed.refs, false))...); err != nil {
		t.Fatalf("resume: %v", err)
	}
	// Only whisker was recorded, so every other unit must still publish. A
	// mis-indexed skip shows up as the wrong directory being left out.
	for _, dir := range []string{"node", "cmd/calico", "istio"} {
		if !slices.Contains(f.targetsFor(dir), "release-publish") {
			t.Errorf("%s was not recorded, so it should have been published", dir)
		}
	}
	if slices.Contains(f.targetsFor("whisker"), "release-publish") {
		t.Error("whisker was already recorded, so it should have been skipped")
	}
}

func TestOnlyMissing(t *testing.T) {
	missing := func(images ...string) error { return &MissingError{Images: images} }
	for _, tc := range []struct {
		name   string
		err    error
		want   []string
		wantOK bool
	}{
		{name: "nil", err: nil},
		{name: "missing", err: missing("a"), want: []string{"a"}, wantOK: true},
		{name: "wrapped", err: fmt.Errorf("step: %w", missing("a")), want: []string{"a"}, wantOK: true},
		{name: "joined", err: errors.Join(missing("a"), fmt.Errorf("x: %w", missing("b"))), want: []string{"a", "b"}, wantOK: true},
		{name: "joined with a lookup error", err: errors.Join(missing("a"), errors.New("unauthorized"))},
		{name: "a lookup error", err: errors.New("unauthorized")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := OnlyMissing(tc.err)
			if ok != tc.wantOK || !slices.Equal(got, tc.want) {
				t.Errorf("OnlyMissing() = %v, %v; want %v, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	resolveOpts := func(f command.CommandRunner, rec steps.RefRecorder) []ResolveOption {
		return []ResolveOption{
			WithRunner(f),
			WithRegistries("quay.io/calico"),
			WithArches("amd64", "arm64"),
			WithRecord(rec),
		}
	}
	absent := func(suffix string) steps.DigestResolver {
		return func(image string) (string, bool, error) {
			if strings.HasSuffix(image, suffix) {
				return "", false, nil
			}
			return "sha256:aaa", true, nil
		}
	}

	t.Run("records the release tag and each arch tag", func(t *testing.T) {
		f := &imageNameRunner{images: "node"}
		rec := &fakeRecorder{}
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"),
			alwaysResolves("sha256:aaa"), resolveOpts(f, rec)...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(rec.refs) != 3 {
			t.Errorf("expected 3 refs (index + 2 arches), got %v", rec.refs)
		}
	})

	t.Run("pushes nothing", func(t *testing.T) {
		f := &imageNameRunner{images: "node"}
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"),
			alwaysResolves("sha256:aaa"), resolveOpts(f, &fakeRecorder{})...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if slices.Contains(f.targetsFor("node"), "release-publish") {
			t.Error("Resolve ran the publish target")
		}
	})

	t.Run("a missing image fails after the rest are recorded", func(t *testing.T) {
		f := &imageNameRunner{perDir: true}
		rec := &fakeRecorder{}
		err := Resolve(testRepoRoot, testVersion,
			[]Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node", "typha", "whisker"}}},
			absent("/typha:"+testVersion), resolveOpts(f, rec)...)
		if err == nil {
			t.Fatal("expected a missing image to fail the run")
		}
		if !strings.Contains(err.Error(), "quay.io/calico/typha:"+testVersion) {
			t.Errorf("error should name the missing image, got %q", err)
		}
		for _, repo := range []string{"quay.io/calico/node@", "quay.io/calico/whisker@"} {
			if !slices.ContainsFunc(rec.refs, func(r string) bool { return strings.HasPrefix(r, repo) }) {
				t.Errorf("%s was not recorded before the failure: %v", repo, rec.refs)
			}
		}
	})

	t.Run("every missing image is named", func(t *testing.T) {
		f := &imageNameRunner{perDir: true}
		err := Resolve(testRepoRoot, testVersion,
			[]Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node", "typha"}}},
			absent(":"+testVersion), resolveOpts(f, &fakeRecorder{})...)
		missing, ok := OnlyMissing(err)
		if !ok {
			t.Fatalf("got %v, want only missing images", err)
		}
		for _, image := range []string{"quay.io/calico/node:" + testVersion, "quay.io/calico/typha:" + testVersion} {
			if !slices.Contains(missing, image) {
				t.Errorf("missing should name %s, got %v", image, missing)
			}
		}
	})

	t.Run("an absent arch tag is not missing", func(t *testing.T) {
		f := &imageNameRunner{images: "node"}
		rec := &fakeRecorder{}
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"),
			absent("-arm64"), resolveOpts(f, rec)...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(rec.refs) != 2 {
			t.Errorf("expected the arm64 tag to be skipped, got %v", rec.refs)
		}
	})

	t.Run("a dir with no images of the variant names what it builds", func(t *testing.T) {
		f := &imageNameRunner{images: "cni-windows"}
		err := Resolve(testRepoRoot, testVersion, oneStandardVariant("cni-plugin"),
			alwaysResolves("sha256:aaa"), resolveOpts(f, &fakeRecorder{})...)
		if err == nil || !strings.Contains(err.Error(), `"cni-windows"`) {
			t.Errorf("error should name the images build-images printed, got %v", err)
		}
	})

	t.Run("a failed lookup is not reported as missing", func(t *testing.T) {
		f := &imageNameRunner{images: "node"}
		resolve := func(string) (string, bool, error) {
			return "", false, fmt.Errorf("network is unreachable")
		}
		err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"),
			resolve, resolveOpts(f, &fakeRecorder{})...)
		if err == nil {
			t.Fatal("expected a failed lookup to fail the run")
		}
		if !strings.Contains(err.Error(), "network is unreachable") {
			t.Errorf("error should carry the cause, got %q", err)
		}
		if _, ok := OnlyMissing(err); ok {
			t.Errorf("a failed lookup was reported as a missing image: %q", err)
		}
	})

	t.Run("a failed lookup keeps what the others found", func(t *testing.T) {
		f := &imageNameRunner{perDir: true}
		rec := &fakeRecorder{}
		failing := []string{"quay.io/calico/node:" + testVersion + "-amd64", "quay.io/calico/typha:" + testVersion}
		resolve := func(image string) (string, bool, error) {
			if slices.Contains(failing, image) {
				return "", false, fmt.Errorf("network is unreachable")
			}
			return "sha256:aaa", true, nil
		}
		err := Resolve(testRepoRoot, testVersion,
			[]Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node", "typha"}}},
			resolve, resolveOpts(f, rec)...)
		for _, image := range failing {
			if err == nil || !strings.Contains(err.Error(), image) {
				t.Errorf("error should name %s, got %v", image, err)
			}
		}
		want := []string{
			"quay.io/calico/node@sha256:aaa", "quay.io/calico/node@sha256:aaa",
			"quay.io/calico/typha@sha256:aaa", "quay.io/calico/typha@sha256:aaa",
		}
		if !slices.Equal(rec.refs, want) {
			t.Errorf("refs %v, want %v", rec.refs, want)
		}
	})

	t.Run("only the first registry must have the release tag", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			absent      string
			wantMissing bool
			wantRefs    []string
		}{
			{
				name:     "absent from a later registry",
				absent:   "docker.io/calico/node:" + testVersion,
				wantRefs: []string{"quay.io/calico/node@sha256:aaa"},
			},
			{
				name:        "absent from the first registry",
				absent:      "quay.io/calico/node:" + testVersion,
				wantMissing: true,
				wantRefs:    []string{"docker.io/calico/node@sha256:aaa"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rec := &fakeRecorder{}
				resolve := func(image string) (string, bool, error) {
					if image == tc.absent {
						return "", false, nil
					}
					return "sha256:aaa", true, nil
				}
				opts := []ResolveOption{
					WithRunner(&imageNameRunner{images: "node"}),
					WithRegistries("quay.io/calico", "docker.io/calico"),
					WithRecord(rec),
				}
				err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"), resolve, opts...)
				if got := err != nil && strings.Contains(err.Error(), tc.absent); got != tc.wantMissing {
					t.Errorf("reported %s missing = %v, want %v (err: %v)", tc.absent, got, tc.wantMissing, err)
				}
				if !slices.Equal(rec.refs, tc.wantRefs) {
					t.Errorf("refs %v, want %v", rec.refs, tc.wantRefs)
				}
			})
		}
	})

	t.Run("a declared variant reads only its tag prefix", func(t *testing.T) {
		f := &imageNameRunner{prefix: "alt", envKey: "ALT_VARIANT=true"}
		rec := &fakeRecorder{}
		variants := []Variant{
			{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}, Images: []string{"whisker"}},
			{Name: "alt", Target: "release-publish", Env: []string{"ALT_VARIANT=true"}, ReleaseDirs: []string{"node"}, Images: []string{"whisker"}},
		}
		var mu sync.Mutex
		var asked []string
		resolve := func(image string) (string, bool, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, image)
			return "sha256:aaa", true, nil
		}
		if err := Resolve(testRepoRoot, testVersion, variants, resolve, resolveOpts(f, rec)...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if slices.Contains(f.targetsFor("node"), "build-images") {
			t.Error("a declared variant read its image names from make")
		}
		for _, image := range []string{
			"quay.io/calico/whisker:" + testVersion,
			"quay.io/calico/whisker:" + testVersion + "-arm64",
			"quay.io/calico/whisker:alt-" + testVersion,
			"quay.io/calico/whisker:alt-" + testVersion + "-amd64",
		} {
			if !slices.Contains(asked, image) {
				t.Errorf("did not resolve %s; asked for %v", image, asked)
			}
		}
		if len(rec.refs) != 6 {
			t.Errorf("expected 6 refs (2 variants x index + 2 arches), got %v", rec.refs)
		}
	})

	t.Run("a failed lookup names the declared image, not its dir", func(t *testing.T) {
		declared := []Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}, Images: []string{"whisker"}}}
		resolve := func(string) (string, bool, error) { return "", false, fmt.Errorf("network is unreachable") }
		err := Resolve(testRepoRoot, testVersion, declared, resolve, resolveOpts(&imageNameRunner{}, &fakeRecorder{})...)
		if err == nil || !strings.Contains(err.Error(), "resolving images for whisker:") {
			t.Errorf("got %v, want it to name whisker", err)
		}
	})

	t.Run("needs a checkout", func(t *testing.T) {
		declared := []Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: []string{"node"}, Images: []string{"whisker"}}}
		err := Resolve("", testVersion, declared,
			alwaysResolves("sha256:aaa"), resolveOpts(&imageNameRunner{}, &fakeRecorder{})...)
		if err == nil || !strings.Contains(err.Error(), "no repository root") {
			t.Errorf("expected a missing repository root to fail, got %v", err)
		}
	})

	t.Run("scans once every image is found", func(t *testing.T) {
		scan, scans := scanServer(t)
		opts := append(resolveOpts(&imageNameRunner{images: "node"}, &fakeRecorder{}), WithScan(scan))
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"), alwaysResolves("sha256:aaa"), opts...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got := len(scans.sent()); got != 1 {
			t.Errorf("sent %d scan requests, want 1", got)
		}
	})

	t.Run("a dry-run scan sends nothing", func(t *testing.T) {
		scan, scans := scanServer(t)
		scan.DryRun = true
		opts := append(resolveOpts(&imageNameRunner{images: "node"}, &fakeRecorder{}), WithScan(scan))
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"), alwaysResolves("sha256:aaa"), opts...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got := len(scans.sent()); got != 0 {
			t.Errorf("a dry run sent %d scan requests", got)
		}
	})

	t.Run("does not scan when an image is missing", func(t *testing.T) {
		scan, scans := scanServer(t)
		opts := append(resolveOpts(&imageNameRunner{images: "node"}, &fakeRecorder{}), WithScan(scan))
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"), absent(":"+testVersion), opts...); err == nil {
			t.Fatal("expected the missing image to fail")
		}
		if got := len(scans.sent()); got != 0 {
			t.Errorf("sent %d scan requests for a run with a missing image", got)
		}
	})

	t.Run("keeps lookups in flight under the limit", func(t *testing.T) {
		var dirs []string
		for i := range 30 {
			dirs = append(dirs, fmt.Sprintf("dir%d", i))
		}
		var inFlight, peak atomic.Int32
		resolve := func(string) (string, bool, error) {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			inFlight.Add(-1)
			return "sha256:aaa", true, nil
		}
		variants := []Variant{{Name: StandardVariant, Target: "release-publish", ReleaseDirs: dirs}}
		if err := Resolve(testRepoRoot, testVersion, variants, resolve,
			resolveOpts(&imageNameRunner{perDir: true}, &fakeRecorder{})...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got, limit := peak.Load(), int32(lookupLimit*lookupLimit); got > limit {
			t.Errorf("%d lookups in flight, want at most %d", got, limit)
		}
	})

	t.Run("needs a registry", func(t *testing.T) {
		err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"),
			alwaysResolves("sha256:aaa"), WithRunner(&imageNameRunner{images: "node"}))
		if err == nil {
			t.Error("expected no registries to fail")
		}
	})
}

type scanLog struct {
	mu    sync.Mutex
	scans [][]string
}

func (l *scanLog) sent() [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.scans)
}

func scanServer(t *testing.T) (*ScanRequest, *scanLog) {
	t.Helper()
	scans := &scanLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Images []string `json:"images"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		scans.mu.Lock()
		scans.scans = append(scans.scans, body.Images)
		scans.mu.Unlock()
		_, _ = w.Write([]byte(`{"results_link": "http://example.com/results"}`))
	}))
	t.Cleanup(srv.Close)
	return &ScanRequest{
		Config:    imagescanner.Config{APIURL: srv.URL, Token: "token", Scanner: "scanner"},
		Images:    []string{"quay.io/calico/node:" + testVersion},
		OutputDir: t.TempDir(),
	}, scans
}

func TestWithDependencies(t *testing.T) {
	const node, dependent = "quay.io/calico/node:" + testVersion, "quay.io/calico/dependent:" + testVersion
	resolveOpts := func(f command.CommandRunner, rec steps.RefRecorder) []ResolveOption {
		return []ResolveOption{WithRunner(f), WithRegistries("quay.io/calico"), WithRecord(rec)}
	}
	withDependent := func(t *testing.T) (*ScanRequest, *scanLog) {
		scan, scans := scanServer(t)
		scan.Images = []string{node, dependent}
		return scan, scans
	}

	t.Run("a failed dependency fails the resolve after recording and holds the scan", func(t *testing.T) {
		scan, scans := withDependent(t)
		rec := &fakeRecorder{}
		dep := func() ([]string, error) { return nil, fmt.Errorf("unauthorized") }
		opts := append(resolveOpts(&imageNameRunner{images: "node"}, rec), WithScan(scan), WithDependencies(dep))
		err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"), alwaysResolves("sha256:aaa"), opts...)
		if err == nil || !strings.Contains(err.Error(), "unauthorized") {
			t.Fatalf("got %v, want the dependency's error", err)
		}
		if len(rec.refs) == 0 {
			t.Error("the images were not recorded")
		}
		if sent := scans.sent(); len(sent) != 0 {
			t.Errorf("sent %v from a failed resolve", sent)
		}
	})

	t.Run("a dependency leaves its unscanned refs out of the scan", func(t *testing.T) {
		scan, scans := withDependent(t)
		dep := func() ([]string, error) { return []string{dependent}, nil }
		opts := append(resolveOpts(&imageNameRunner{images: "node"}, &fakeRecorder{}), WithScan(scan), WithDependencies(dep))
		if err := Resolve(testRepoRoot, testVersion, oneStandardVariant("node"), alwaysResolves("sha256:aaa"), opts...); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if sent := scans.sent(); len(sent) != 1 || !slices.Equal(sent[0], []string{node}) {
			t.Errorf("sent %v, want one scan of %s", sent, node)
		}
		if !slices.Equal(scan.Images, []string{node, dependent}) {
			t.Errorf("the request was changed to %v", scan.Images)
		}
	})

	t.Run("a failed dependency holds the publish scan", func(t *testing.T) {
		scan, scans := withDependent(t)
		dep := func() ([]string, error) { return nil, fmt.Errorf("unauthorized") }
		opts := recordingOpts(&imageNameRunner{images: "node"}, &fakeRecorder{}, WithScan(scan), WithDependencies(dep))
		if err := Publish(testRepoRoot, testVersion, oneStandardVariant("node"), true, alwaysResolves("sha256:aaa"), opts...); err == nil {
			t.Fatal("expected the dependency's error to fail the publish")
		}
		if sent := scans.sent(); len(sent) != 0 {
			t.Errorf("sent %v from a failed publish", sent)
		}
	})
}

func TestRecord(t *testing.T) {
	t.Run("keeps what a unit found before a lookup failed", func(t *testing.T) {
		f := &imageNameRunner{images: "node"}
		rec := &fakeRecorder{}
		resolve := func(image string) (string, bool, error) {
			if strings.HasSuffix(image, "-amd64") {
				return "", false, fmt.Errorf("network is unreachable")
			}
			return "sha256:aaa", true, nil
		}
		err := Publish(testRepoRoot, testVersion, oneStandardVariant("node"), true, resolve, recordingOpts(f, rec)...)
		if err == nil || !strings.Contains(err.Error(), "network is unreachable") {
			t.Fatalf("expected the failed lookup to be reported, got %v", err)
		}
		want := []string{"quay.io/calico/node@sha256:aaa", "quay.io/calico/node@sha256:aaa"}
		if !slices.Equal(rec.refs, want) {
			t.Errorf("refs %v, want %v", rec.refs, want)
		}
	})
}
