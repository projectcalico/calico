package postrelease

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	"github.com/spf13/cast"
	"go.yaml.in/yaml/v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"

	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/github"
	"github.com/projectcalico/calico/release/internal/registry"
)

// chartURLs returns the GitHub release download URLs for every released chart.
// The release tag keeps the "v" prefix; the chart archive names use the semver
// chart version, which does not.
func chartURLs(t testing.TB, githubOrg, githubRepo, version string) []string {
	t.Helper()
	urls := []string{}
	for _, name := range charts.All() {
		u, err := github.DownloadURL(githubOrg, githubRepo, version, charts.FileName(name, charts.Version(version, "")))
		if err != nil {
			t.Fatal(err)
		}
		urls = append(urls, u)
	}
	return urls
}

func TestHelmChart(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	t.Run("github", func(t *testing.T) {
		t.Parallel()

		for _, url := range chartURLs(t, githubOrg, githubRepo, releaseVersion) {
			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("failed to fetch helm chart: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("failed to fetch helm chart: server returned %s", resp.Status)
			}
			defer func() { _ = resp.Body.Close() }()

			chart, err := loader.LoadArchive(resp.Body)
			if err != nil {
				t.Fatalf("load helm chart: %v", err)
			}
			validateChart(t, chart)
		}
	})

	t.Run("OCI registry", func(t *testing.T) {
		t.Parallel()

		for _, reg := range registry.DefaultHelmRegistries {
			t.Run(reg, func(t *testing.T) {
				t.Parallel()

				for _, chart := range charts.All() {
					t.Run(chart, func(t *testing.T) {
						t.Parallel()
						dir := t.TempDir()
						chartVersion := charts.Version(releaseVersion, "")
						args := []string{
							"pull", fmt.Sprintf("oci://%s/%s", reg, chart),
							"--version", chartVersion,
						}
						out, err := command.RunInDir(dir, "helm", args)
						if err != nil {
							t.Fatalf("pull %s %s helm chart from %s: %v\nOutput: %s", chart, chartVersion, reg, err, out)
						}
						chart, err := loader.Load(filepath.Join(dir, charts.FileName(chart, chartVersion)))
						if err != nil {
							t.Fatalf("load helm chart from %s: %v", reg, err)
						}
						validateChart(t, chart)

					})
				}

			})
		}
	})
}

func validateChart(t testing.TB, chart *chart.Chart) {
	t.Helper()
	if err := chart.Validate(); err != nil {
		t.Fatalf("invalid helm chart: %v", err)
	}
	// The chart version is semver, so it carries no "v" prefix, while the
	// appVersion names the Calico release and does.
	if want := charts.Version(releaseVersion, ""); chart.Metadata.Version != want {
		t.Fatalf("expected helm chart version %s, got %s", want, chart.Metadata.Version)
	}
	if chart.AppVersion() != releaseVersion {
		t.Fatalf("expected helm chart app version %s, got %s", releaseVersion, chart.AppVersion())
	}
}

func TestHelmIndex(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	repoURL, err := charts.RepoURL()
	if err != nil {
		t.Fatal(err)
	}
	indexURL, err := url.JoinPath(repoURL, "index.yaml")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(indexURL)
	if err != nil {
		t.Fatalf("failed to fetch helm index: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching helm index: %s", resp.Status)
	}
	var index struct {
		Entries map[string][]map[string]any `yaml:"entries"`
	}
	if err := yaml.NewDecoder(resp.Body).Decode(&index); err != nil {
		t.Fatalf("failed to decode helm index: %v", err)
	}

	// The index is keyed by chart version, which is semver and so has no "v" prefix.
	chartVersion := charts.Version(releaseVersion, "")

	// Each chart has its own entry, carrying only its own download url.
	for _, name := range charts.All() {
		entries, ok := index.Entries[name]
		if !ok || len(entries) == 0 {
			t.Errorf("helm index has no %s entries", name)
			continue
		}
		matching := slices.Collect(func(yield func(map[string]any) bool) {
			for _, entry := range entries {
				if entry["version"] == chartVersion {
					yield(entry)
				}
			}
		})
		if len(matching) != 1 {
			t.Errorf("helm index has %d %s entries for %s, want 1", len(matching), name, chartVersion)
			continue
		}
		want, err := github.DownloadURL(githubOrg, githubRepo, releaseVersion, charts.FileName(name, chartVersion))
		if err != nil {
			t.Fatal(err)
		}
		if urls := cast.ToStringSlice(matching[0]["urls"]); !slices.Contains(urls, want) {
			t.Errorf("%s entry for %s has urls %v, want %q", name, chartVersion, urls, want)
		}
	}
}
