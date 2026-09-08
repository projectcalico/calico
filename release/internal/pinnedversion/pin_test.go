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

package pinnedversion

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-cmp/cmp"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var dateApprovalScrubber = approvals.NewDateScrubber(`[a-zA-Z]{3}, \d{1,2} [a-zA-Z]{3} \d{4} \d{2}:\d{2}:\d{2} [A-Z]{3}`)

const testProductVersion = "v3.31.0"

// testImageComponent is a component every product builds an image for, so a
// shared test can assert on it.
const testImageComponent = "node"

// testComponents are the pinned components a test pin carries. A product with
// a different component set replaces this in init().
var testComponents = func() map[string]registry.Component {
	return map[string]registry.Component{
		apiComponentName:              {Version: testProductVersion},
		calicoComponentName:           {Version: testProductVersion},
		networkingCalicoComponentName: {Version: "release-v3.31"},
		flannelComponentName:          FlannelComponent,
		testImageComponent:            {Version: testProductVersion},
	}
}

// testPin is a pin with the fields the file layout depends on, so approval
// output does not move with the working tree.
func testPin() *Pin {
	return &Pin{
		ReleaseName:    "test-release",
		Hash:           testProductVersion,
		Note:           "test-release - generated at Mon, 01 Sep 2026 00:00:00 UTC using release-v3.31 release branch",
		ProductVersion: testProductVersion,
		branch:         "release-v3.31",
		Operator: registry.Component{
			Image:    operator.DefaultImage,
			Registry: operator.DefaultRegistries[0],
			Version:  testProductVersion,
		},
		Components: testComponents(),
	}
}

// The approval guards the file's shape: key names, nesting and order. It uses
// a fixed component set so it does not move with the product's own.
func TestWritePin(t *testing.T) {
	dir := t.TempDir()
	p := testPin()
	p.Components = map[string]registry.Component{
		testImageComponent: {Version: testProductVersion},
		"third-party":      {Version: "v1.2.3", Image: "vendor/third-party", Registry: "quay.io"},
	}
	if err := write(p, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	content, err := os.ReadFile(FilePath(dir))
	if err != nil {
		t.Fatalf("reading pinned version file: %v", err)
	}
	approvals.VerifyString(t, string(content), approvals.Options().WithScrubber(dateApprovalScrubber))
}

func TestWriteCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tmp")
	if err := write(testPin(), dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(FilePath(dir)); err != nil {
		t.Fatalf("pinned version file not created: %v", err)
	}
}

// A round trip must not drop what the pin carries, since a later command reads
// the file rather than re-deriving it.
func TestWriteThenRead(t *testing.T) {
	dir := t.TempDir()
	want := testPin()
	if err := write(want, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := read(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, tc := range []struct{ name, want, got string }{
		{"release name", want.ReleaseName, got.ReleaseName},
		{"hash", want.Hash, got.Hash},
		{"note", want.Note, got.Note},
		{"product version", want.ProductVersion, got.ProductVersion},
		{"operator version", want.Operator.Version, got.Operator.Version},
	} {
		if tc.want != tc.got {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, tc.got)
		}
	}
	if diff := cmp.Diff(want.Components, got.Components); diff != "" {
		t.Errorf("components differ: %s", diff)
	}
}

// Which components are excluded is a per-product list, so the expectation is
// derived from it rather than restating one product's answer.
func TestImages(t *testing.T) {
	p := testPin()
	// Pin the product's own excluded components, so the exclusion is exercised
	// whichever set this build uses.
	if len(noImageComponents) == 0 {
		t.Fatal("no excluded components to test against")
	}
	for _, name := range noImageComponents {
		p.Components[name] = registry.Component{Version: testProductVersion}
	}

	got := p.Images()
	for _, name := range noImageComponents {
		if _, ok := got[name]; ok {
			t.Errorf("%s produces no image but is in the map", name)
		}
	}
	// A component that names no image of its own takes the component name.
	if c, ok := got[testImageComponent]; !ok {
		t.Errorf("%s missing from the image map", testImageComponent)
	} else if c.Image != componentImage(testImageComponent) {
		t.Errorf("%s: want image %q, got %q", testImageComponent,
			componentImage(testImageComponent), c.Image)
	}
	// A component that names its own image keeps it.
	for name, c := range p.Components {
		if c.Image == "" || slices.Contains(noImageComponents, name) {
			continue
		}
		if got[name].Image != c.Image {
			t.Errorf("%s: want its own image %q, got %q", name, c.Image, got[name].Image)
		}
	}
	if got[testPin().Operator.Image].Image != testPin().Operator.Image {
		t.Error("the operator is missing from the image map")
	}
}

func TestImageNames(t *testing.T) {
	names := testPin().ImageNames()
	if !slices.IsSorted(names) {
		t.Errorf("image names are not sorted: %v", names)
	}
	for _, want := range []string{componentImage(testImageComponent), testPin().Operator.Image} {
		if !slices.Contains(names, want) {
			t.Errorf("%q missing from %v", want, names)
		}
	}
}

// componentImage lets a product name an image differently from its component.
func TestImagesWithComponentImageOverride(t *testing.T) {
	original := componentImage
	componentImage = func(name string) string {
		if name == testImageComponent {
			return "renamed"
		}
		return original(name)
	}
	defer func() { componentImage = original }()

	if got := testPin().Images()[testImageComponent].Image; got != "renamed" {
		t.Errorf("want renamed, got %q", got)
	}
}

func TestHelmChartVersion(t *testing.T) {
	for _, tc := range []struct {
		name         string
		chartVersion string
		want         string
	}{
		{"empty shares the product version", "", "v3.31.0"},
		{"non-empty qualifies it", "2", "v3.31.0-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPin()
			p.ChartVersion = tc.chartVersion
			if got := p.HelmChartVersion(); got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestComponentVersion(t *testing.T) {
	p := testPin()
	if got := p.ComponentVersion(testImageComponent); got != testProductVersion {
		t.Errorf("want v3.31.0, got %q", got)
	}
	if got := p.ComponentVersion("absent"); got != "" {
		t.Errorf("want empty for an absent component, got %q", got)
	}
}

func TestHashreleaseCarriesComponents(t *testing.T) {
	h := testPin().Hashrelease("/base", true)
	if h.Source != filepath.Join("/base", "v3.31.0") {
		t.Errorf("unexpected source: %q", h.Source)
	}
	if !h.Latest {
		t.Error("latest not set")
	}
	if diff := cmp.Diff(testPin().Components, h.Components); diff != "" {
		t.Errorf("component differs (-want +got): %s", diff)
	}
}

// A second load must not rename a hashrelease the first one may have published.
func TestLoadReusesExistingPin(t *testing.T) {
	dir := t.TempDir()
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	cfg := Config{Dir: dir, RootDir: root, ReleaseBranchPrefix: "release"}

	first, err := Load(LocalLoader{Config: cfg})
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	second, err := Load(LocalLoader{Config: cfg})
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}

	if isDirty(t, root) {
		// A dirty tree re-pins by design, so only the version can be compared.
		if first.ProductVersion != second.ProductVersion {
			t.Errorf("product version changed: %q then %q", first.ProductVersion, second.ProductVersion)
		}
		return
	}
	if first.ReleaseName != second.ReleaseName {
		t.Errorf("release name changed: %q then %q", first.ReleaseName, second.ReleaseName)
	}
	if first.Hash != second.Hash {
		t.Errorf("hash changed: %q then %q", first.Hash, second.Hash)
	}
}

// The file does not record the branch, but it decides the publish stream, so
// a reused pin must resolve it rather than publish to the wrong stream.
func TestReusedPinKeepsStream(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	branch, err := utils.GitBranch(root)
	if err != nil {
		t.Fatalf("git branch: %v", err)
	}
	productVer, err := productVersion(root)
	if err != nil {
		t.Fatalf("product version: %v", err)
	}
	dir := t.TempDir()
	fresh := testPin()
	fresh.ProductVersion = productVer
	fresh.SetBranch(branch)
	if err := write(fresh, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reused, err := Load(LocalLoader{Config: Config{Dir: dir, RootDir: root, ReleaseBranchPrefix: "release"}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := reused.Hashrelease("", false).Stream, fresh.Hashrelease("", false).Stream; got != want {
		t.Errorf("reused pin stream %q, want %q", got, want)
	}
}

// A pin from an older product version belongs to another build.
func TestLoadReplacesStalePin(t *testing.T) {
	dir := t.TempDir()
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	stale := testPin()
	stale.ProductVersion = "v0.0.1"
	if err := write(stale, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Load(LocalLoader{Config: Config{Dir: dir, RootDir: root, ReleaseBranchPrefix: "release"}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ProductVersion == "v0.0.1" {
		t.Error("stale pin reused instead of replaced")
	}
}

// "--dirty" describes every working state the same way, so a matching version
// is not proof of matching inputs.
func TestLoadReplacesDirtyPin(t *testing.T) {
	dir := t.TempDir()
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	if !isDirty(t, root) {
		t.Skip("working tree is clean")
	}
	productVer, err := productVersion(root)
	if err != nil {
		t.Fatalf("product version: %v", err)
	}
	existing := testPin()
	existing.ProductVersion = productVer
	existing.ReleaseName = "should-not-be-reused"
	if err := write(existing, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Load(LocalLoader{Config: Config{Dir: dir, RootDir: root, ReleaseBranchPrefix: "release"}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ReleaseName == "should-not-be-reused" {
		t.Error("dirty pin reused instead of replaced")
	}
}

// A fresh generate returns the pin and writes it to every dir.
func TestLocalLoaderGenerates(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	dir, hashreleaseBase := t.TempDir(), t.TempDir()

	got, err := Load(LocalLoader{Config: Config{
		Dir: dir, HashreleaseDir: hashreleaseBase, RootDir: root,
		ReleaseBranchPrefix: "release",
	}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned no pin")
	}
	if got.ReleaseName == "" || got.ProductVersion == "" {
		t.Errorf("pin is not fully resolved: %+v", got)
	}
	// The hashrelease copy lands under the hash, which is only known once the
	// pin is generated.
	for _, want := range []string{dir, filepath.Join(hashreleaseBase, got.Hash)} {
		if _, statErr := os.Stat(FilePath(want)); statErr != nil {
			t.Errorf("no pinned version file in %s: %v", want, statErr)
		}
	}
}

// FileLoader reads a pin without touching a repository.
func TestFileLoader(t *testing.T) {
	dir := t.TempDir()
	want := testPin()
	if err := write(want, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Load(FileLoader{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ReleaseName != want.ReleaseName {
		t.Errorf("want %q, got %q", want.ReleaseName, got.ReleaseName)
	}
}

func TestFileLoaderMissingFile(t *testing.T) {
	if _, err := Load(FileLoader{Dir: t.TempDir()}); err == nil {
		t.Error("want an error for a missing file, got none")
	}
}

func TestReuseRules(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	productVer, err := productVersion(root)
	if err != nil {
		t.Fatalf("product version: %v", err)
	}
	dirty := strings.HasSuffix(productVer, "-dirty")

	local := LocalLoader{Config: Config{RootDir: root}}
	same := testPin()
	same.ProductVersion = productVer
	if got := local.Reuse(same); got == dirty {
		t.Errorf("matching product version: reuse=%v, tree dirty=%v", got, dirty)
	}
	other := testPin()
	other.ProductVersion = "v0.0.1"
	if local.Reuse(other) {
		t.Error("reused a pin from another product version")
	}

}

func isDirty(t *testing.T, dir string) bool {
	t.Helper()
	v, err := command.GitVersion(dir, true)
	if err != nil {
		t.Fatalf("git version: %v", err)
	}
	return len(v) > 6 && v[len(v)-6:] == "-dirty"
}

// The pin is written to the first dir and copied to the rest, so a hashrelease
// keeps its own copy of what it was built from.
func TestWriteCopiesToEveryDir(t *testing.T) {
	first := t.TempDir()
	second := filepath.Join(t.TempDir(), "nested")
	third := filepath.Join(t.TempDir(), "also", "nested")

	if err := write(testPin(), first, second, third); err != nil {
		t.Fatalf("Write: %v", err)
	}

	want, err := os.ReadFile(FilePath(first))
	if err != nil {
		t.Fatalf("reading the first copy: %v", err)
	}
	for _, dir := range []string{second, third} {
		got, err := os.ReadFile(FilePath(dir))
		if err != nil {
			t.Errorf("reading the copy in %s: %v", dir, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("copy in %s differs from the first write", dir)
		}
	}
}

// One unwritable dir must not hide the others, and must not stop the
// writable ones from being written.
func TestWriteReportsEveryFailure(t *testing.T) {
	good := t.TempDir()
	bad1, bad2 := t.TempDir(), t.TempDir()
	for _, d := range []string{bad1, bad2} {
		// A directory where the file belongs makes os.Create fail.
		if err := os.MkdirAll(FilePath(d), 0o755); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	err := write(testPin(), good, bad1, bad2)
	if err == nil {
		t.Fatal("want an error, got none")
	}
	for _, d := range []string{bad1, bad2} {
		if !strings.Contains(err.Error(), d) {
			t.Errorf("error does not mention %s: %v", d, err)
		}
	}
	if _, statErr := os.Stat(FilePath(good)); statErr != nil {
		t.Errorf("the writable dir was not written: %v", statErr)
	}
}

func TestWriteNoDir(t *testing.T) {
	if err := write(testPin()); err == nil {
		t.Error("want an error when no dir is given, got none")
	}
}

func TestReadErrors(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"missing file", ""},
		{"not yaml", "\t: not: valid\n"},
		{"empty list", "[]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.content != "" {
				if err := os.WriteFile(FilePath(dir), []byte(tc.content), 0o644); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}
			if _, err := read(dir); err == nil {
				t.Error("want an error, got none")
			}
		})
	}
}

// A reused pin is returned as-is. Falling through to generate would mint a new
// release name and orphan whatever the first one published.
func TestLocalLoaderReuseDoesNotRegenerate(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	// Accept whatever is on disk, so the reuse path runs whether or not the
	// working tree happens to be clean.
	original := localCheck
	localCheck = func(LocalLoader, *Pin) bool { return true }
	defer func() { localCheck = original }()

	dir := t.TempDir()
	existing := testPin()
	existing.ReleaseName = "must-be-reused"
	if err := write(existing, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Load(LocalLoader{Config: Config{
		Dir: dir, RootDir: root, ReleaseBranchPrefix: "release",
	}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ReleaseName != "must-be-reused" {
		t.Errorf("reuse regenerated the pin: got %q", got.ReleaseName)
	}
}

// A generated pin is persisted through writePin, not Write directly. A product
// whose file carries fields Pin does not model replaces that seam, so a Load
// that bypassed it would drop those fields with no error.
func TestLocalLoaderWritesThroughTheSeam(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	called := false
	original := writePin
	writePin = func(cfg Config, p *Pin, dirs ...string) error {
		called = true
		return original(cfg, p, dirs...)
	}
	defer func() { writePin = original }()

	dir := t.TempDir()
	if _, err := Load(LocalLoader{Config: Config{
		Dir: dir, RootDir: root, ReleaseBranchPrefix: "release",
	}}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !called {
		t.Error("Load bypassed writePin")
	}
}

// The chart version survives a round trip through the file. It is written as
// helmRelease, so a pin() that skipped it would silently return the bare
// product version from HelmChartVersion.
func TestPinCarriesChartVersion(t *testing.T) {
	entry := PinnedVersion{Title: "v3.22.0", HelmRelease: "3"}
	p := entry.pin()
	if p.ChartVersion != "3" {
		t.Errorf("chart version lost on read: got %q", p.ChartVersion)
	}
	if got := p.HelmChartVersion(); got != "v3.22.0-3" {
		t.Errorf("HelmChartVersion: got %q, want v3.22.0-3", got)
	}
}

// FileLoader picks up the branch when RootDir is set, because the branch and
// not the version decides an early-preview stream.
func TestFileLoaderSetsBranch(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	dir := t.TempDir()
	if err := write(testPin(), dir); err != nil {
		t.Fatalf("write: %v", err)
	}

	withRoot, err := Load(FileLoader{Dir: dir, RootDir: root})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if withRoot.branch == "" {
		t.Error("RootDir was set but the branch was not resolved")
	}

	// A pin that records no branch has nothing to recover, so RootDir is the
	// only source left.
	bare := t.TempDir()
	noBranch := testPin()
	noBranch.branch = ""
	noBranch.Note = ""
	if err := write(noBranch, bare); err != nil {
		t.Fatalf("write: %v", err)
	}
	without, err := Load(FileLoader{Dir: bare})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if without.branch != "" {
		t.Errorf("branch resolved with neither RootDir nor a recorded branch: %q", without.branch)
	}
}

// The file's own branch wins over the checkout's. A pin built on one branch
// and published from another must keep the branch it was pinned from, or it
// publishes to the wrong stream.
func TestFileLoaderKeepsRecordedBranch(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	dir := t.TempDir()
	p := testPin()
	p.SetBranch("master")
	if err := write(p, dir); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Load(FileLoader{Dir: dir, RootDir: root})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.branch != "master" {
		t.Errorf("recorded branch replaced by the checkout: got %q", got.branch)
	}
	if stream := got.Hashrelease("", false).Stream; stream != "master" {
		t.Errorf("stream %q, want master", stream)
	}
}

func TestFileLoaderRequiresDir(t *testing.T) {
	if _, err := Load(FileLoader{}); err == nil {
		t.Error("want an error when no dir is given, got none")
	}
}

// Config.Valid reports every missing input at once, so one run names all of
// them rather than one per attempt.
func TestConfigValid(t *testing.T) {
	full := Config{RootDir: "/repo", Dir: "/tmp", ReleaseBranchPrefix: "release"}
	if err := full.Valid(); err != nil {
		t.Errorf("want no error for a complete config, got %v", err)
	}
	err := Config{}.Valid()
	if err == nil {
		t.Fatal("want an error for an empty config, got none")
	}
	for _, want := range []string{"root dir", "dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	// An invalid repo is reported against its position.
	err = Config{RootDir: "/repo", Dir: "/tmp", Repos: []Repo{{}}}.Valid()
	if err == nil || !strings.Contains(err.Error(), "repo 0") {
		t.Errorf("want the repo index named, got %v", err)
	}
}

// Every loader validates before doing any work. Asserting only that an error
// came back would not catch a loader that skipped Valid and failed later, so
// this asserts on aggregation: Valid names every missing input, where failing
// later reports only the first thing to break.
func TestLoadValidatesFirst(t *testing.T) {
	for name, loader := range map[string]Loader{
		"file":  FileLoader{},
		"local": LocalLoader{Config: Config{}},
	} {
		_, err := Load(loader)
		if err == nil {
			t.Errorf("%s loader: want an error before any work, got none", name)
		}
	}

	// LocalLoader is the one whose later failure looks the same as Valid's, so
	// it needs the aggregation check to tell them apart.
	_, err := Load(LocalLoader{Config: Config{}})
	if err == nil {
		t.Fatal("local loader: want an error, got none")
	}
	for _, want := range []string{"root dir is required", "dir is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("local loader did not validate up front: error %q omits %q", err, want)
		}
	}
}

// A loader with no dir has nothing to read, and must say so rather than fail
// deeper with a confusing file error.
func TestLoaderValidRequiresDir(t *testing.T) {
	for name, err := range map[string]error{
		"file":  FileLoader{}.Valid(),
		"local": LocalLoader{}.Valid(),
	} {
		if err == nil {
			t.Errorf("%s loader: want an error with no dir, got none", name)
		}
	}
}

// stubLoader stands in for a loader that fails, so Load's error path can be
// tested without a repository.
type stubLoader struct {
	pin      *Pin
	validErr error
	err      error
}

func (l stubLoader) Valid() error { return l.validErr }

func (l stubLoader) Load() (*Pin, error) { return l.pin, l.err }

// Load returns the loader's error unchanged.
func TestLoadPropagatesLoaderError(t *testing.T) {
	if _, err := Load(stubLoader{err: os.ErrInvalid}); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("want the loader's error, got %v", err)
	}
}

// A failing source must not leave a pinned version file behind.
func TestLocalLoaderSourceErrorWritesNothing(t *testing.T) {
	root, err := command.GitDir()
	if err != nil {
		t.Fatalf("git root: %v", err)
	}
	original := productComponents
	productComponents = func(Config, string) (map[string]registry.Component, error) {
		return nil, os.ErrInvalid
	}
	defer func() { productComponents = original }()

	dir := t.TempDir()
	if _, err := Load(LocalLoader{Config: Config{Dir: dir, RootDir: root, ReleaseBranchPrefix: "release"}}); err == nil {
		t.Fatal("want the source's error, got none")
	}
	if _, statErr := os.Stat(FilePath(dir)); statErr == nil {
		t.Error("a failed load wrote a pinned version file")
	}
}

func TestImagesSkipsNoImageComponents(t *testing.T) {
	p := &Pin{
		Components: map[string]registry.Component{
			testImageComponent: {Version: testProductVersion},
		},
	}
	for _, name := range noImageComponents {
		p.Components[name] = registry.Component{Version: "v3.31.0"}
	}
	got := p.Images()
	for _, name := range noImageComponents {
		if _, ok := got[name]; ok {
			t.Errorf("%s produces no image but is in the map", name)
		}
	}
	if _, ok := got[testImageComponent]; !ok {
		t.Errorf("%s is missing from the image map", testImageComponent)
	}
}

// The operator is only added when it names an image, so a pin read without one
// does not gain an empty entry.
func TestImagesOperatorOptional(t *testing.T) {
	p := &Pin{Components: map[string]registry.Component{testImageComponent: {Version: testProductVersion}}}
	if _, ok := p.Images()[""]; ok {
		t.Error("an operator with no image was added to the map")
	}
	p.Operator = registry.Component{Image: operator.DefaultImage, Version: testProductVersion}
	if _, ok := p.Images()[operator.DefaultImage]; !ok {
		t.Error("the operator is missing from the image map")
	}
}
