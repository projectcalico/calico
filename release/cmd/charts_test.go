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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
)

// What the chart commands are expected to drive. A product whose charts differ
// replaces these rather than the assertions, so the suite is shared rather
// than rewritten.
var (
	// The product version, as the manifests carry it.
	chartsCLITestVersion = "v3.30.0"

	// The version in a chart's file name. A product that qualifies its charts
	// with a suffix replaces this.
	chartsCLIChartVersion = chartsCLITestVersion

	// Where a build leaves the packaged charts. A product that writes them
	// somewhere other than a per-version directory replaces this.
	chartsCLIChartDir = func(cfg *Config) string {
		return charts.Dir(filepath.Join(cfg.OutputDir, chartsCLITestVersion))
	}

	// The make target that packages every chart.
	chartsCLITarget = "chart"

	// A registry to publish to, and the digest a published chart resolves to.
	chartsCLIRegistry = "quay.test/charts"
	chartsCLIDigest   = "sha256:aaa"

	// The repository whose index a build merges with.
	chartsCLIRepoURL = func(t *testing.T) string {
		t.Helper()
		u, err := charts.RepoURL()
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	// A product serving charts from the repository it indexes replaces this:
	// there the two URLs coincide.
	chartsCLICheckDownloadURL = func(t *testing.T, url string) {
		t.Helper()
		if repo := chartsCLIRepoURL(t); url == repo {
			t.Errorf("expected the download url to differ from the repository url %q", repo)
		}
		if !strings.Contains(url, chartsCLITestVersion) {
			t.Errorf("expected the download url to name the release, got %q", url)
		}
	}
)

// The chart list is a product's own, so a test must not hardcode a member.
func chartsCLIFirstChart(t *testing.T) string {
	t.Helper()
	names := charts.All()
	if len(names) == 0 {
		t.Fatal("no release charts to test against")
	}
	return names[0]
}

// runCharts drives the real charts command with a recording runner. It returns
// the runner and the config, so a test can assert on what reached disk.
var runCharts = func(t *testing.T, args ...string) (*recordingRunner, *Config) {
	t.Helper()
	root := fakeRepo(t, chartsCLITestVersion)
	cfg := &Config{
		RepoRootDir: root,
		TmpDir:      filepath.Join(root, "tmp"),
		OutputDir:   filepath.Join(root, "_output"),
		LogsDir:     filepath.Join(root, "_logs"),
	}
	// The chart target does not really run, so the packages it would have
	// written are staged for the steps that read them back.
	writeFakeCharts(t, cfg)
	return runChartsIn(t, cfg, args...), cfg
}

// runChartsIn drives the charts command against an existing config, so a test
// can run twice over one output directory.
func runChartsIn(t *testing.T, cfg *Config, args ...string) *recordingRunner {
	t.Helper()
	r := &recordingRunner{}
	prev, prevResolve := commandRunner, registryDigestResolver
	commandRunner = r
	registryDigestResolver = func(string) (string, bool, error) { return chartsCLIDigest, true, nil }
	t.Cleanup(func() { commandRunner, registryDigestResolver = prev, prevResolve })

	cmd := chartsCommand(cfg)
	if err := cmd.Run(context.Background(), append([]string{"charts"}, args...)); err != nil {
		t.Fatalf("charts %s: %v", strings.Join(args, " "), err)
	}
	return r
}

func writeFakeCharts(t *testing.T, cfg *Config) {
	t.Helper()
	dir := chartsCLIChartDir(cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range charts.All() {
		path := filepath.Join(dir, charts.FileName(name, chartsCLIChartVersion))
		if err := os.WriteFile(path, []byte("chart"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func TestChartsBuildRunsTheChartTarget(t *testing.T) {
	r, cfg := runCharts(t, "build", "--no-helm-index")

	if !r.ran(chartsCLITarget) {
		t.Fatalf("expected the %q target to run", chartsCLITarget)
	}
	env := r.envFor(chartsCLITarget)
	if !slices.Contains(env, "GIT_VERSION="+chartsCLIChartVersion) {
		t.Error("expected GIT_VERSION in the build environment")
	}
	want := "CHART_DESTINATION=" + chartsCLIChartDir(cfg)
	if !slices.Contains(env, want) {
		t.Errorf("expected %q in the build environment, got %v", want, env)
	}
}

// Building the index reaches the network; opting out must stay offline.
func TestChartsBuildSkipsTheIndexWhenDisabled(t *testing.T) {
	r, _ := runCharts(t, "build", "--no-helm-index")

	if r.ran("repo", "index") {
		t.Error("expected no index build when --no-helm-index is set")
	}
	if r.ran("curl") {
		t.Error("expected no index download when --no-helm-index is set")
	}
}

func TestChartsBuildBuildsTheIndexByDefault(t *testing.T) {
	r, cfg := runCharts(t, "build")

	if !r.ran("repo", "index") {
		t.Fatal("expected the index to be built by default")
	}
	// Merging keeps the entries the repository already served; replacing would
	// drop every earlier release.
	if !r.ran("--merge") {
		t.Error("expected the published index to be merged rather than replaced")
	}
	if repo := chartsCLIRepoURL(t); !r.ran(repo) {
		t.Errorf("expected the index at %q to be downloaded", repo)
	}
	// The index sits with the charts, so a sweep of the output takes both.
	indexDir := chartsCLIChartDir(cfg)
	if _, err := os.Stat(filepath.Join(indexDir, "index.yaml")); err != nil {
		t.Errorf("expected the index in %q: %v", indexDir, err)
	}
}

// Swapping these two would point clients at the wrong host.
func TestChartsBuildIndexPointsAtTheDownloadURL(t *testing.T) {
	r, _ := runCharts(t, "build")

	var urlArg string
	for _, args := range r.args {
		if i := slices.Index(args, "--url"); i >= 0 && i+1 < len(args) {
			urlArg = args[i+1]
		}
	}
	if urlArg == "" {
		t.Fatal("expected the index to be given a download url")
	}
	chartsCLICheckDownloadURL(t, urlArg)
}

func TestChartsBuildLogsUnderItsOwnStep(t *testing.T) {
	r, cfg := runCharts(t, "build", "--no-helm-index")

	want := filepath.Join(cfg.LogsDir, "charts-build", "charts.log")
	if !slices.Contains(r.logPaths, want) {
		t.Errorf("expected a build log at %q, got %v", want, r.logPaths)
	}
}

func TestChartsPublishPushesEveryChart(t *testing.T) {
	r, _ := runCharts(t, "publish", "--helm-registry", chartsCLIRegistry)

	for _, name := range charts.All() {
		if !r.ran("push", charts.FileName(name, chartsCLIChartVersion)) {
			t.Errorf("expected %s to be pushed", name)
		}
	}
	if !r.ran("push", "oci://"+chartsCLIRegistry) {
		t.Errorf("expected the push to reach oci://%s", chartsCLIRegistry)
	}
}

func TestChartsPublishLocalPushesNothing(t *testing.T) {
	r, _ := runCharts(t, "publish", "--local", "--helm-registry", chartsCLIRegistry)

	if r.ran("push") {
		t.Error("expected --local to push nothing")
	}
}

func TestChartsPublishLocalRecordsNothing(t *testing.T) {
	_, cfg := runCharts(t, "publish", "--local", "--helm-registry", chartsCLIRegistry)

	refs, err := outputs.ReadRefs(cfg.OutputDir, charts.PublishStep, chartsCLIChartVersion)
	if err != nil {
		t.Fatalf("reading refs: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected a dry run to record nothing, got %v", refs)
	}
}

func TestChartsPublishRecordsWhatItPushed(t *testing.T) {
	_, cfg := runCharts(t, "publish", "--helm-registry", chartsCLIRegistry)

	refs, err := outputs.ReadRefs(cfg.OutputDir, charts.PublishStep, chartsCLIChartVersion)
	if err != nil {
		t.Fatalf("reading refs: %v", err)
	}
	if len(refs) != len(charts.All()) {
		t.Fatalf("expected one ref per chart, got %d: %v", len(refs), refs)
	}
	want := chartsCLIRegistry + "/" + chartsCLIFirstChart(t) + "@" + chartsCLIDigest
	if !slices.Contains(refs, want) {
		t.Errorf("expected %q in the record, got %v", want, refs)
	}
}

func TestChartsPublishLogsPerChart(t *testing.T) {
	r, cfg := runCharts(t, "publish", "--helm-registry", chartsCLIRegistry)

	dir := filepath.Join(cfg.LogsDir, "charts-publish")
	if !slices.ContainsFunc(r.logPaths, func(p string) bool { return strings.HasPrefix(p, dir) }) {
		t.Errorf("expected publish logs under %q, got %v", dir, r.logPaths)
	}
	// A chart goes to several registries, so its log names both.
	want := chartsCLIFirstChart(t) + "-"
	if !slices.ContainsFunc(r.logPaths, func(p string) bool {
		return strings.HasPrefix(filepath.Base(p), want)
	}) {
		t.Errorf("expected a log named for %q, got %v", want, r.logPaths)
	}
}

func TestChartsPublishResumesFromTheRecord(t *testing.T) {
	first, cfg := runCharts(t, "publish", "--helm-registry", chartsCLIRegistry)
	if !first.ran("push") {
		t.Fatal("expected the first publish to push")
	}

	// The second run reads the record the first wrote, so every chart is
	// already published at the digest the registry still serves.
	second := runChartsIn(t, cfg, "publish", "--helm-registry", chartsCLIRegistry)
	if second.ran("push") {
		t.Error("expected a resumed publish to push nothing")
	}
}

func TestChartsPublishForceRepublishesOverAMovedDigest(t *testing.T) {
	_, cfg := runCharts(t, "publish", "--helm-registry", chartsCLIRegistry)

	prev, prevResolve := commandRunner, registryDigestResolver
	r := &recordingRunner{}
	commandRunner = r
	registryDigestResolver = func(string) (string, bool, error) { return "sha256:moved", true, nil }
	t.Cleanup(func() { commandRunner, registryDigestResolver = prev, prevResolve })

	cmd := chartsCommand(cfg)
	args := []string{"charts", "publish", "--helm-registry", chartsCLIRegistry, "--force"}
	if err := cmd.Run(context.Background(), args); err != nil {
		t.Fatalf("charts publish --force: %v", err)
	}
	if !r.ran("push") {
		t.Error("expected --force to republish over the moved digest")
	}
}

// Without --force the disagreement is an error, not a silent republish.
func TestChartsPublishFailsOnAMovedDigestWithoutForce(t *testing.T) {
	_, cfg := runCharts(t, "publish", "--helm-registry", chartsCLIRegistry)

	prev, prevResolve := commandRunner, registryDigestResolver
	r := &recordingRunner{}
	commandRunner = r
	registryDigestResolver = func(string) (string, bool, error) { return "sha256:moved", true, nil }
	t.Cleanup(func() { commandRunner, registryDigestResolver = prev, prevResolve })

	cmd := chartsCommand(cfg)
	args := []string{"charts", "publish", "--helm-registry", chartsCLIRegistry}
	err := cmd.Run(context.Background(), args)
	if err == nil {
		t.Fatal("expected a moved digest to fail the publish")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("expected the error to name --force, got %v", err)
	}
	if r.ran("push") {
		t.Error("expected nothing pushed on a digest disagreement")
	}
}

// A hashrelease pins its own versions and serves its own charts.
func TestChartsBuildForAHashrelease(t *testing.T) {
	const pinned = "v3.30.0-1-gabc"
	// Stub the pin, not the resolver: the chart identity and the options it
	// derives are what this test is for.
	// Only the build source is stubbed: a build must not read the published pin.
	prevBuild, prevPublish := pinForBuild, pinForPublish
	pinForBuild = func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
		return &pinnedversion.Pin{
			ProductVersion:  pinned,
			ProductRegistry: chartsCLIRegistry,
			Hash:            "abc123",
			ReleaseName:     "gentle-otter",
			Operator: registry.Component{
				Version:  "v1.40.0-1-gdef",
				Image:    "tigera/operator",
				Registry: chartsCLIRegistry,
			},
		}, nil
	}
	pinForPublish = func(*Config, *cli.Command) (*pinnedversion.Pin, error) {
		return nil, fmt.Errorf("build must not load the published pin")
	}
	t.Cleanup(func() { pinForBuild, pinForPublish = prevBuild, prevPublish })

	// The build verifies what the target packaged, so stage the pinned version.
	prevVer, prevDir := chartsCLIChartVersion, chartsCLIChartDir
	chartsCLIChartVersion = pinned
	chartsCLIChartDir = func(cfg *Config) string {
		return charts.Dir(filepath.Join(baseHashreleaseOutputDir(cfg.RepoRootDir), "abc123"))
	}
	t.Cleanup(func() { chartsCLIChartVersion, chartsCLIChartDir = prevVer, prevDir })

	r, cfg := runCharts(t, "build", "--hashrelease")

	values, err := os.ReadFile(filepath.Join(cfg.RepoRootDir, "charts", charts.TigeraOperatorChart, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(values), pinned) {
		t.Errorf("expected the chart values rewritten to %s, got %q", pinned, values)
	}
	if !r.ran("--url", "gentle-otter") {
		t.Error("expected the index to point at the hashrelease")
	}
	if r.ran("--url", "releases/download") {
		t.Error("expected no GitHub release url for a hashrelease")
	}
}

func TestChartsBuildForAReleaseDoesNotRewriteValues(t *testing.T) {
	r, _ := runCharts(t, "build", "--no-helm-index")

	if r.ran("sed") {
		t.Error("expected no values rewritten for a release build")
	}
}

// A hashrelease's charts sit under the hashrelease output dir, keyed by hash:
// that is where the hashrelease flow writes them and reads them back.
func TestHashreleaseChartDirMatchesTheHashreleaseFlow(t *testing.T) {
	prev := pinForBuild
	pin := &pinnedversion.Pin{ProductVersion: "v3.30.0-1-gabc", Hash: "abc123", ReleaseName: "gentle-otter"}
	pinForBuild = func(*Config, *cli.Command) (*pinnedversion.Pin, error) { return pin, nil }
	t.Cleanup(func() { pinForBuild = prev })

	root := t.TempDir()
	cfg := &Config{RepoRootDir: root, OutputDir: filepath.Join(root, "release", "_output")}
	c := &cli.Command{Flags: []cli.Flag{hashreleaseFlag}}
	if err := c.Run(context.Background(), []string{"x", "--hashrelease"}); err != nil {
		t.Fatal(err)
	}
	chart, err := pinnedChart(cfg, c, pinForBuild)
	if err != nil {
		t.Fatalf("pinnedChart: %v", err)
	}
	want := charts.Dir(pin.Hashrelease(baseHashreleaseOutputDir(root), false).Source)
	if chart.BaseDir != want {
		t.Errorf("BaseDir = %q, want %q", chart.BaseDir, want)
	}
}

// A product may qualify its charts with a suffix, so the chart version and the
// product version differ. The build stamps and the publish record must both
// follow the resolved chart version, not the product one.
func TestChartsFollowTheResolvedChartVersion(t *testing.T) {
	const suffix = "0"
	resolved := chartsCLITestVersion + "-" + suffix

	prevChart, prevVer := pinnedChart, chartsCLIChartVersion
	pinnedChart = func(cfg *Config, c *cli.Command, pin pinned) (*charts.Chart, error) {
		chart, err := prevChart(cfg, c, pin)
		if err != nil {
			return nil, err
		}
		chart.ChartVersion = suffix
		return chart, nil
	}
	chartsCLIChartVersion = resolved
	t.Cleanup(func() { pinnedChart, chartsCLIChartVersion = prevChart, prevVer })

	r, cfg := runCharts(t, "build", "--no-helm-index")
	if !slices.Contains(r.envFor(chartsCLITarget), "GIT_VERSION="+resolved) {
		t.Errorf("GIT_VERSION did not follow the chart version, env: %v", r.envFor(chartsCLITarget))
	}

	runChartsIn(t, cfg, "publish", "--helm-registry", chartsCLIRegistry)
	// A missing record reads as empty rather than an error, so count the refs.
	refs, err := outputs.ReadRefs(cfg.OutputDir, charts.PublishStep, resolved)
	if err != nil {
		t.Fatalf("reading refs: %v", err)
	}
	if len(refs) != len(charts.All()) {
		t.Errorf("record under %s has %d refs, want %d", resolved, len(refs), len(charts.All()))
	}
}
