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

package charts

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/yamledit"
)

// fakeRunner records every invocation and can fail a command a set number of
// times before succeeding, to exercise the retry.
type fakeRunner struct {
	mu    sync.Mutex
	calls []call
	// failures maps a key from failKey to how many times it should fail.
	failures map[string]int
	// staged is what the index directory held when helm was asked to index it.
	staged []string
	// onRun stands in for a command's side effects on the tree.
	onRun func(env []string)
}

type call struct {
	name string
	args []string
	env  []string
	// logPath is empty when output was captured in memory.
	logPath string
}

func (f *fakeRunner) RunInDir(_, name string, args, env []string) (string, error) {
	return f.record(name, args, env, "")
}

func (f *fakeRunner) RunInDirToFile(_, name string, args, env []string, logPath string) (string, error) {
	return f.record(name, args, env, logPath)
}

func (f *fakeRunner) Run(name string, args, env []string) (string, error) {
	return f.record(name, args, env, "")
}

func (f *fakeRunner) record(name string, args, env []string, logPath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{name: name, args: slices.Clone(args), env: slices.Clone(env), logPath: logPath})
	if f.onRun != nil {
		f.onRun(env)
	}
	// Stand in for helm: `repo index <dir>` writes the index into that dir.
	if name == helmBinary && len(args) > 2 && args[0] == "repo" && args[1] == "index" {
		if entries, err := os.ReadDir(args[2]); err == nil {
			for _, e := range entries {
				f.staged = append(f.staged, e.Name())
			}
		}
		_ = os.WriteFile(filepath.Join(args[2], indexFileName), []byte("entries:"), 0o644)
	}
	if n, ok := f.failures[failKey(name, args)]; ok && n > 0 {
		f.failures[failKey(name, args)] = n - 1
		return "boom", fmt.Errorf("command failed")
	}
	return "ok", nil
}

func (f *fakeRunner) RunNoCapture(string, []string, []string) error              { return nil }
func (f *fakeRunner) RunInDirNoCapture(string, string, []string, []string) error { return nil }

// Keyed on chart file plus destination: keying on the command alone could not
// tell two pushes apart, and would hide a mistargeted one.
func failKey(name string, args []string) string {
	if name == helmBinary && len(args) > 2 && args[0] == "push" {
		return filepath.Base(args[1]) + " " + args[2]
	}
	return name
}

func (f *fakeRunner) pushes() []string {
	var out []string
	for _, c := range f.calls {
		if c.name == helmBinary && len(c.args) > 2 && c.args[0] == "push" {
			out = append(out, filepath.Base(c.args[1])+" "+c.args[2])
		}
	}
	slices.Sort(out)
	return out
}

func (f *fakeRunner) callsTo(name string) []call {
	var out []call
	for _, c := range f.calls {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

func hasEnv(env []string, want string) bool {
	return slices.Contains(env, want)
}

// A resolver answering every chart alike cannot catch a skip of the wrong one.
func resolvesPerChart(digests map[string]string) steps.DigestResolver {
	return func(ref string) (string, bool, error) {
		for chart, digest := range digests {
			if strings.Contains(ref, "/"+chart+":") {
				return digest, true, nil
			}
		}
		return "", false, nil
	}
}

// testChart is a neutral fixture: the package takes the chart list as data, so
// no product's real chart names belong here.
func testChart(t *testing.T) Chart {
	t.Helper()
	dir := t.TempDir()
	return Chart{
		RepoRoot:       dir,
		ProductVersion: "v3.30.0",
		Names:          []string{"chart-one", "chart-two"},
		BaseDir:        filepath.Join(dir, "output"),
	}
}

func writeCharts(t *testing.T, c Chart, names ...string) {
	t.Helper()
	if err := os.MkdirAll(c.BaseDir, 0o755); err != nil {
		t.Fatalf("creating chart dir: %v", err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(c.BaseDir, FileName(name, c.Version())), []byte("chart"), 0o644); err != nil {
			t.Fatalf("writing chart %s: %v", name, err)
		}
	}
}

func TestBuildRunsChartTargetOnce(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	if err := Build(c, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Charts may nest as sub-charts, so make sequences them in one invocation.
	makes := f.callsTo("make")
	if len(makes) != 1 {
		t.Fatalf("expected one make invocation, got %d", len(makes))
	}
	if !slices.Contains(makes[0].args, chartTarget) {
		t.Errorf("expected the %q target, got %v", chartTarget, makes[0].args)
	}
	if !hasEnv(makes[0].env, "GIT_VERSION=v3.30.0") {
		t.Error("expected GIT_VERSION in the build environment")
	}
	if !hasEnv(makes[0].env, "CHART_DESTINATION="+c.BaseDir) {
		t.Error("expected CHART_DESTINATION in the build environment")
	}
}

func TestBuildPassesExtraEnv(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	if err := Build(c, WithRunner(f), WithEnv("RELEASE_STREAM=v3.30")); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !hasEnv(f.callsTo("make")[0].env, "RELEASE_STREAM=v3.30") {
		t.Error("expected the caller's extra environment to reach the target")
	}
}

func TestBuildFailsWhenAChartIsMissing(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, "chart-one")

	err := Build(c, WithRunner(&fakeRunner{}))
	if err == nil {
		t.Fatal("expected a build that packaged only one chart to fail")
	}
	if !strings.Contains(err.Error(), "chart-two") {
		t.Errorf("expected the missing chart to be named, got %v", err)
	}
}

func TestBuildRestoresTreeAfterModifyingValues(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	path := writeChartValues(t, c.RepoRoot, "chart-one", "version: master\n")

	if err := Build(c, WithRunner(f), WithModifiedValues([]ValueEdit{{Chart: "chart-one", Edit: yamledit.Edit{Key: "version", To: "v3.30.0"}}})); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "version: v3.30.0\n" {
		t.Errorf("values not modified, got %q", got)
	}
	if len(f.callsTo("git")) != 1 {
		t.Error("expected the chart tree to be restored after the build")
	}
}

func TestBuildRestoresTreeWhenBuildFails(t *testing.T) {
	c := testChart(t)
	f := &fakeRunner{failures: map[string]int{"make": 1}}

	if err := Build(c, WithRunner(f), WithModifiedValues([]ValueEdit{{Chart: "chart-one", Edit: yamledit.Edit{Key: "version", To: "v3.30.0"}}})); err == nil {
		t.Fatal("expected the build to fail")
	}
	if len(f.callsTo("git")) != 1 {
		t.Error("expected the chart tree to be restored after a failed build")
	}
}

// Building the index reaches the network; packaging charts must not.
func TestBuildDoesNotBuildTheIndex(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	if err := Build(c, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(f.callsTo("curl")) != 0 {
		t.Error("expected a build not to download the index")
	}
	if len(f.callsTo(helmBinary)) != 0 {
		t.Error("expected a build not to invoke helm")
	}
}

func TestBuildRejectsIncompleteCharts(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Chart)
	}{
		{"no repo root", func(c *Chart) { c.RepoRoot = "" }},
		{"no version", func(c *Chart) { c.ProductVersion = "" }},
		{"no charts", func(c *Chart) { c.Names = nil }},
		{"unnamed chart", func(c *Chart) { c.Names = []string{"chart-one", ""} }},
		{"no chart dir", func(c *Chart) { c.BaseDir = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testChart(t)
			tc.mut(&c)
			if err := Build(c, WithRunner(&fakeRunner{})); err == nil {
				t.Fatal("expected an incomplete chart set to be rejected")
			}
		})
	}
}

// The step name is the log directory, so the slug is what keeps a build and an
// index build apart.
func TestBuildLogsUnderItsOwnStep(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}
	logs := filepath.Join(t.TempDir(), "logs")

	if err := Build(c, WithRunner(f), WithLogsDir(logs)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := filepath.Join(logs, buildStep, "charts.log")
	if got := f.callsTo("make")[0].logPath; got != want {
		t.Errorf("log path: got %q, want %q", got, want)
	}
}

func TestBuildWithoutLogsDirCapturesInMemory(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	if err := Build(c, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := f.callsTo("make")[0].logPath; got != "" {
		t.Errorf("expected in-memory capture, got log path %q", got)
	}
}

const (
	testRepoURL  = "https://example.test/charts"
	testChartURL = "https://example.test/download/v3.30.0"
)

func TestBuildIndexMergesThePublishedIndex(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}
	indexDir := filepath.Join(t.TempDir(), "index")

	if err := Build(c, WithRunner(f),
		WithIndex(testRepoURL, testChartURL, indexDir, filepath.Join(c.RepoRoot, "tmp"))); err != nil {
		t.Fatalf("Build: %v", err)
	}

	curls := f.callsTo("curl")
	if len(curls) != 1 {
		t.Fatalf("expected the published index to be downloaded once, got %d", len(curls))
	}
	if !slices.Contains(curls[0].args, testRepoURL+"/"+indexFileName) {
		t.Errorf("expected the repo index url to be fetched, got %v", curls[0].args)
	}

	helms := f.callsTo(helmBinary)
	if len(helms) != 1 {
		t.Fatalf("expected one helm invocation, got %d", len(helms))
	}
	// Merging keeps the entries the repository already served; replacing would
	// drop every earlier release from the index.
	if !slices.Contains(helms[0].args, "--merge") {
		t.Error("expected the published index to be merged rather than replaced")
	}
	// The index tells clients where to download from, which is not the
	// repository it was merged from.
	if !slices.Contains(helms[0].args, testChartURL) {
		t.Error("expected the index to point at the chart url")
	}
	if slices.Contains(helms[0].args, testRepoURL) {
		t.Error("expected the repo url not to be used as the download url")
	}
	// helm indexes a whole directory, so it must be pointed at one holding
	// only this release's charts, not the output directory.
	dir := helms[0].args[2]
	if dir == c.BaseDir {
		t.Error("expected the index built over a staging dir, not the chart dir")
	}
	for _, name := range c.Names {
		if !slices.Contains(f.staged, FileName(name, c.Version())) {
			t.Errorf("expected %s staged for the index, got %v", name, f.staged)
		}
	}
	if _, err := os.Stat(filepath.Join(indexDir, indexFileName)); err != nil {
		t.Errorf("expected the finished index in %s: %v", indexDir, err)
	}
}

// helm stamps entries with the current time, so UTC keeps the index stable.
func TestBuildIndexUsesUTC(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	if err := Build(c, WithRunner(f),
		WithIndex(testRepoURL, testChartURL, filepath.Join(t.TempDir(), "index"), t.TempDir())); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !hasEnv(f.callsTo(helmBinary)[0].env, "TZ=UTC") {
		t.Error("expected the index to be built in UTC")
	}
}

// Linking fails on an existing file, so a rebuild must clear the old link.
func TestBuildIndexIsRepeatable(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	indexDir := filepath.Join(t.TempDir(), "index")
	tmp := t.TempDir()

	for i := range 2 {
		if err := Build(c, WithRunner(&fakeRunner{}),
			WithIndex(testRepoURL, testChartURL, indexDir, tmp)); err != nil {
			t.Fatalf("Build run %d: %v", i, err)
		}
	}
}

// The index builds within the chart build, so the slug is what keeps their
// logs apart.
func TestBuildIndexLogsBesideTheCharts(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}
	logs := filepath.Join(t.TempDir(), "logs")

	if err := Build(c, WithRunner(f), WithLogsDir(logs),
		WithIndex(testRepoURL, testChartURL, filepath.Join(t.TempDir(), "index"), t.TempDir())); err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := filepath.Join(logs, buildStep, "index.log")
	if got := f.callsTo(helmBinary)[0].logPath; got != want {
		t.Errorf("log path: got %q, want %q", got, want)
	}
}

func TestBuildIndexRejectsMissingLocations(t *testing.T) {
	for _, tc := range []struct{ name, repoURL, chartURL, indexDir string }{
		{"no repo url", "", testChartURL, "index"},
		{"no chart url", testRepoURL, "", "index"},
		{"no index dir", testRepoURL, testChartURL, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testChart(t)
			if err := Build(c, WithRunner(&fakeRunner{}),
				WithIndex(tc.repoURL, tc.chartURL, tc.indexDir, t.TempDir())); err == nil {
				t.Fatal("expected an index build missing a location to be rejected")
			}
		})
	}
}

func publishable(t *testing.T) Chart {
	t.Helper()
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	return c
}

// Each push names its own file: pushing one chart repeatedly would pass a
// count-only check.
func TestPublishPushesEveryChartToEveryRegistry(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}

	if err := Publish(c, []string{"quay.test/charts", "docker.test/charts"}, true, WithRunner(f)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	want := []string{
		"chart-one-v3.30.0.tgz oci://docker.test/charts",
		"chart-one-v3.30.0.tgz oci://quay.test/charts",
		"chart-two-v3.30.0.tgz oci://docker.test/charts",
		"chart-two-v3.30.0.tgz oci://quay.test/charts",
	}
	if got := f.pushes(); !slices.Equal(got, want) {
		t.Errorf("pushes:\n got %v\nwant %v", got, want)
	}
}

func TestPublishRetriesAFailedPush(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{failures: map[string]int{"chart-one-v3.30.0.tgz oci://quay.test/charts": 1}}

	if err := Publish(c, []string{"quay.test/charts"}, true, WithRunner(f)); err != nil {
		t.Fatalf("expected the retry to recover the push: %v", err)
	}
	if got := len(f.pushes()); got != 3 {
		t.Errorf("expected the failed push to be retried, got %d pushes", got)
	}
}

func TestPublishReportsFailureAfterRetriesExhausted(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{failures: map[string]int{"chart-one-v3.30.0.tgz oci://quay.test/charts": 99}}

	err := Publish(c, []string{"quay.test/charts"}, true, WithRunner(f))
	if err == nil {
		t.Fatal("expected the publish to fail")
	}
	if !strings.Contains(err.Error(), "chart-one") {
		t.Errorf("expected the failing chart to be named, got %v", err)
	}
	if !slices.Contains(f.pushes(), "chart-two-v3.30.0.tgz oci://quay.test/charts") {
		t.Error("expected the other chart to be published despite the failure")
	}
}

func TestPublishFailsBeforePushingWhenAChartIsMissing(t *testing.T) {
	c := publishable(t)
	if err := os.Remove(filepath.Join(c.BaseDir, FileName("chart-two", c.Version()))); err != nil {
		t.Fatalf("removing chart: %v", err)
	}
	f := &fakeRunner{}

	if err := Publish(c, []string{"quay.test/charts"}, true, WithRunner(f)); err == nil {
		t.Fatal("expected a publish with a missing chart to fail")
	}
	if got := f.pushes(); len(got) != 0 {
		t.Errorf("expected nothing to be pushed, got %v", got)
	}
}

func TestPublishRejectsNoRegistries(t *testing.T) {
	if err := Publish(publishable(t), nil, true, WithRunner(&fakeRunner{})); err == nil {
		t.Fatal("expected a publish with no registries to be rejected")
	}
}

func TestPublishLogsPerChartAndRegistry(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}
	logs := filepath.Join(t.TempDir(), "logs")

	if err := Publish(c, []string{"quay.test/charts"}, true, WithRunner(f), WithLogsDir(logs)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// A chart goes to several registries, so the slug carries both.
	want := filepath.Join(logs, PublishStep, "chart-one-quay.test-charts.log")
	if !slices.ContainsFunc(f.callsTo(helmBinary), func(c call) bool { return c.logPath == want }) {
		t.Errorf("expected a per-chart log at %q", want)
	}
}

// recorder collects the refs a publish records.
type recorder struct {
	mu   sync.Mutex
	refs []string
}

func (r *recorder) Add(refs ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs = append(r.refs, refs...)
	return nil
}

// A resolver answering every chart alike could not catch a mismatched digest.
func TestPublishRecordsWhatItPushed(t *testing.T) {
	c := publishable(t)
	rec := &recorder{}

	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(&fakeRunner{}),
		WithResolver(resolvesPerChart(map[string]string{
			"chart-one": "sha256:aaa",
			"chart-two": "sha256:bbb",
		})),
		WithRecord(rec))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	want := []string{
		"quay.test/charts/chart-one@sha256:aaa",
		"quay.test/charts/chart-two@sha256:bbb",
	}
	if !slices.Equal(rec.refs, want) {
		t.Errorf("recorded refs:\n got %v\nwant %v", rec.refs, want)
	}
}

func TestPublishDryRunPushesAndRecordsNothing(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}
	rec := &recorder{}

	if err := Publish(c, []string{"quay.test/charts"}, false,
		WithRunner(f), WithResolver(resolvesPerChart(map[string]string{"chart-one": "sha256:aaa"})),
		WithRecord(rec)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := f.pushes(); len(got) != 0 {
		t.Errorf("expected a dry run to push nothing, got %v", got)
	}
	if len(rec.refs) != 0 {
		t.Errorf("expected a dry run to record nothing, got %v", rec.refs)
	}
}

func TestPublishResumeSkipsChartsAlreadyPublished(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}

	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(f),
		WithResolver(resolvesPerChart(map[string]string{
			"chart-one": "sha256:aaa",
			"chart-two": "sha256:bbb",
		})),
		WithResume([]string{"quay.test/charts/chart-one@sha256:aaa"}, false))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Only chart-two is left. A resolver answering every chart alike could not
	// tell this from skipping the wrong one.
	want := []string{"chart-two-v3.30.0.tgz oci://quay.test/charts"}
	if got := f.pushes(); !slices.Equal(got, want) {
		t.Errorf("pushes:\n got %v\nwant %v", got, want)
	}
}

// A digest disagreeing with the record means the tag moved under us.
func TestPublishResumeFailsOnDigestMismatch(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}

	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(f),
		WithResolver(resolvesPerChart(map[string]string{"chart-one": "sha256:zzz"})),
		WithResume([]string{"quay.test/charts/chart-one@sha256:aaa"}, false))
	if err == nil {
		t.Fatal("expected a digest mismatch to fail the publish")
	}
	for _, want := range []string{"chart-one", "sha256:zzz", "sha256:aaa", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected %q in the error, got %v", want, err)
		}
	}
	if got := f.pushes(); len(got) != 0 {
		t.Errorf("expected nothing pushed on a mismatch, got %v", got)
	}
}

func TestPublishResumeForceRepublishesOverAMismatch(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}

	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(f),
		WithResolver(resolvesPerChart(map[string]string{"chart-one": "sha256:zzz"})),
		WithResume([]string{"quay.test/charts/chart-one@sha256:aaa"}, true))
	if err != nil {
		t.Fatalf("Publish with force: %v", err)
	}
	if !slices.Contains(f.pushes(), "chart-one-v3.30.0.tgz oci://quay.test/charts") {
		t.Error("expected force to republish the mismatched chart")
	}
}

func TestPublishResumePublishesUnrecordedCharts(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}

	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(f),
		WithResolver(resolvesPerChart(map[string]string{"chart-one": "sha256:aaa"})),
		WithResume(nil, false))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := len(f.pushes()); got != 2 {
		t.Errorf("expected both charts published with an empty record, got %d", got)
	}
}

// Pinned to a literal: deriving it from FileName would pass for any format.
func TestFileName(t *testing.T) {
	const want = "chart-one-v3.30.0.tgz"
	if got := FileName("chart-one", "v3.30.0"); got != want {
		t.Errorf("FileName = %q, want %q", got, want)
	}
}

func TestDir(t *testing.T) {
	if got, want := Dir("out"), "out/charts"; got != want {
		t.Errorf("Dir = %q, want %q", got, want)
	}
}

// The version is what keeps one release's charts apart from another's in a
// shared directory, so an empty one is a caller mistake rather than a default.
func TestVersionedDir(t *testing.T) {
	got, err := versionedDir("out", "v3.30.0")
	if err != nil {
		t.Fatalf("versionedDir: %v", err)
	}
	if want := "out/charts-v3.30.0"; got != want {
		t.Errorf("versionedDir = %q, want %q", got, want)
	}
	if _, err := versionedDir("out", ""); err == nil {
		t.Error("expected an empty version to be rejected")
	}
}

// With both charts recorded, resolving the wrong one would skip a chart that
// never landed.
func TestPublishResumeJudgesEachChartByItsOwnDigest(t *testing.T) {
	c := publishable(t)
	f := &fakeRunner{}

	// chart-one still matches its record; chart-two has moved.
	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(f),
		WithResolver(resolvesPerChart(map[string]string{
			"chart-one": "sha256:aaa",
			"chart-two": "sha256:zzz",
		})),
		WithResume([]string{
			"quay.test/charts/chart-one@sha256:aaa",
			"quay.test/charts/chart-two@sha256:bbb",
		}, false))
	if err == nil {
		t.Fatal("expected chart-two's moved digest to fail the publish")
	}
	if !strings.Contains(err.Error(), "chart-two") {
		t.Errorf("expected chart-two named in the error, got %v", err)
	}
	if strings.Contains(err.Error(), "chart-one") {
		t.Errorf("expected chart-one not to be blamed, got %v", err)
	}
}

// A failed lookup must not discard the charts that did land.
func TestPublishRecordsPartialRefsWhenALookupFails(t *testing.T) {
	c := publishable(t)
	rec := &recorder{}

	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(&fakeRunner{}),
		WithResolver(func(ref string) (string, bool, error) {
			if strings.Contains(ref, "chart-two") {
				return "", false, fmt.Errorf("registry unreachable")
			}
			return "sha256:aaa", true, nil
		}),
		WithRecord(rec))
	if err == nil {
		t.Fatal("expected the failed lookup to be reported")
	}
	want := "quay.test/charts/chart-one@sha256:aaa"
	if !slices.Contains(rec.refs, want) {
		t.Errorf("expected %q recorded despite the failure, got %v", want, rec.refs)
	}
}

// A modify that fails partway has already written some edits.
func TestBuildRestoresTreeWhenModifyingValuesFails(t *testing.T) {
	c := testChart(t)
	f := &fakeRunner{}
	// No values file to edit, so the modify fails before the build runs.

	if err := Build(c, WithRunner(f), WithModifiedValues([]ValueEdit{{Chart: "chart-one", Edit: yamledit.Edit{Key: "version", To: "v3.30.0"}}})); err == nil {
		t.Fatal("expected the build to fail")
	}
	if len(f.callsTo("git")) != 1 {
		t.Errorf("expected the chart tree to be restored, got %d git calls", len(f.callsTo("git")))
	}
}

// A release that uploads its whole output directory needs the index inside it.
func TestBuildLeavesTheIndexWhereAsked(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	// Such a release points the index at its own output directory.
	indexDir := filepath.Join(c.BaseDir, "charts")

	if err := Build(c, WithRunner(&fakeRunner{}),
		WithIndex(testRepoURL, testChartURL, indexDir, filepath.Join(c.RepoRoot, "tmp"))); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := os.Stat(filepath.Join(indexDir, indexFileName)); err != nil {
		t.Errorf("expected the index in %s: %v", indexDir, err)
	}
}

// Values are rewritten only when a caller asks, so a plain build leaves the
// tree alone.
func TestBuildWithoutModifiedValuesLeavesTheTree(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	if err := Build(c, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(f.callsTo("git")); got != 0 {
		t.Errorf("expected no tree reset, got %d git calls", got)
	}
}

func TestBuildModifiesValuesWhenAsked(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	f := &fakeRunner{}

	path := writeChartValues(t, c.RepoRoot, "chart-one", "version: master\n")

	if err := Build(c, WithRunner(f), WithModifiedValues([]ValueEdit{
		{Chart: "chart-one", Edit: yamledit.Edit{Key: "version", To: "v3.30.0"}},
	})); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "version: v3.30.0\n" {
		t.Errorf("values not rewritten, got %q", got)
	}
	if got := len(f.callsTo("git")); got != 1 {
		t.Errorf("expected the tree restored, got %d git calls", got)
	}
}

// An empty suffix means the charts share the product version; a suffix means
// they rev separately from it.
func TestVersion(t *testing.T) {
	if got := Version("v3.30.0", ""); got != "v3.30.0" {
		t.Errorf("Version without a suffix = %q, want v3.30.0", got)
	}
	if got := Version("v3.30.0", "2"); got != "v3.30.0-2" {
		t.Errorf("Version with a suffix = %q, want v3.30.0-2", got)
	}
}

// The digest ref must name the resolved version, not the bare suffix.
func TestPublishRefsNameTheResolvedVersion(t *testing.T) {
	// A suffix is what makes the resolved version differ from the product one.
	c := testChart(t)
	c.ChartVersion = "2"
	writeCharts(t, c, c.Names...)
	rec := &recorder{}
	err := Publish(c, []string{"quay.test/charts"}, true,
		WithRunner(&fakeRunner{}),
		WithResolver(func(ref string) (string, bool, error) {
			if !strings.Contains(ref, ":"+c.Version()) {
				t.Errorf("ref %q does not name version %q", ref, c.Version())
			}
			return "sha256:aaa", true, nil
		}),
		WithRecord(rec))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
}

// The staging dir holds only this run's charts, so a chart dropped from the
// build does not linger in the next index.
func TestBuildIndexDropsStaleCharts(t *testing.T) {
	c := testChart(t)
	writeCharts(t, c, c.Names...)
	tmp := t.TempDir()

	staging, err := versionedDir(tmp, c.Version())
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(staging, "gone-"+c.Version()+".tgz")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := &fakeRunner{}
	if err := Build(c, WithRunner(f),
		WithIndex(testRepoURL, testChartURL, filepath.Join(t.TempDir(), "index"), tmp)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if slices.Contains(f.staged, filepath.Base(stale)) {
		t.Errorf("stale chart %s was indexed, staged: %v", filepath.Base(stale), f.staged)
	}
}

// The make target names its output by GIT_VERSION, so a chart version suffix
// must reach it: otherwise the build looks for a file the target never wrote.
func TestBuildWithAChartVersionSuffix(t *testing.T) {
	c := testChart(t)
	c.ChartVersion = "2"

	var gitVersion string
	f := &fakeRunner{}
	if err := os.MkdirAll(c.BaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Stage under the name the make target produces for the GIT_VERSION it is given.
	stage := func(env []string) {
		for _, e := range env {
			if v, ok := strings.CutPrefix(e, "GIT_VERSION="); ok {
				gitVersion = v
			}
		}
		for _, name := range c.Names {
			_ = os.WriteFile(filepath.Join(c.BaseDir, FileName(name, gitVersion)), []byte("chart"), 0o644)
		}
	}
	f.onRun = stage

	if err := Build(c, WithRunner(f)); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if want := c.Version(); gitVersion != want {
		t.Errorf("GIT_VERSION = %q, want %q", gitVersion, want)
	}
}

// An edit naming From replaces that value rather than the whole line: a file
// with two lines under one key needs the old value to tell them apart, and a
// bare swap has no key at all.
func TestModifyValues(t *testing.T) {
	root := t.TempDir()
	path := writeChartValues(t, root, "chart-one", "version: master\nimage: quay.io/calico/node # keep\n")

	err := ModifyValues(Values{RepoRoot: root, Edits: []ValueEdit{
		{Chart: "chart-one", Edit: yamledit.Edit{Key: "version", To: "v3.30.0"}},
	}}, WithRunner(&fakeRunner{}))
	if err != nil {
		t.Fatalf("ModifyValues: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "version: v3.30.0\nimage: quay.io/calico/node # keep\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A key the chart no longer has would otherwise ship an unstamped chart.
func TestModifyValuesFailsWhenAKeyIsMissing(t *testing.T) {
	root := t.TempDir()
	writeChartValues(t, root, "chart-one", "version: master\n")

	err := ModifyValues(Values{RepoRoot: root, Edits: []ValueEdit{
		{Chart: "chart-one", Edit: yamledit.Edit{Key: "renamed", To: "v3.30.0"}},
	}}, WithRunner(&fakeRunner{}))
	if err == nil {
		t.Fatal("expected a missing key to fail")
	}
}

func writeChartValues(t *testing.T, root, chart, content string) string {
	t.Helper()
	dir := filepath.Join(root, chartsDirName, chart)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, valuesFileName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
