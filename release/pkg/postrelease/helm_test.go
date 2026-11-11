package postrelease

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
)

func chartURLs(githubOrg, githubRepo, version string) map[string]string {
	urls := map[string]string{}
	for _, chart := range utils.AllReleaseCharts() {
		u := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s-%s.tgz", githubOrg, githubRepo, version, chart, version)
		urls[chart] = u
	}
	return urls
}

func TestHelmChart(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	t.Run("github", func(t *testing.T) {
		t.Parallel()

		for _, url := range chartURLs(githubOrg, githubRepo, releaseVersion) {
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

				for _, chart := range utils.AllReleaseCharts() {
					t.Run(chart, func(t *testing.T) {
						t.Parallel()
						dir := t.TempDir()
						args := []string{
							"pull", fmt.Sprintf("oci://%s/%s", reg, chart),
							"--version", releaseVersion,
						}
						out, err := command.RunInDir(dir, "helm", args)
						if err != nil {
							t.Fatalf("pull %s %s helm chart from %s: %v\nOutput: %s", utils.TigeraOperatorChart, releaseVersion, reg, err, out)
						}
						chart, err := loader.Load(filepath.Join(dir, fmt.Sprintf("%s-%s.tgz", chart, releaseVersion)))
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
	if chart.AppVersion() != releaseVersion {
		t.Fatalf("expected helm chart app version %s, got %s", releaseVersion, chart.AppVersion())
	}
}

type helmIndex struct {
	Entries map[string][]map[string]any `yaml:"entries"`
}

func TestHelmIndex(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	indexURL, err := url.JoinPath(utils.CalicoHelmRepoURL, "index.yaml")
	if err != nil {
		t.Fatalf("construct helm index url: %v", err)
	}
	resp, err := http.Get(indexURL)
	if err != nil {
		t.Fatalf("failed to fetch helm index: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to fetch helm index: server returned %s", resp.Status)
	}
	defer func() { _ = resp.Body.Close() }()
	index := helmIndex{}
	if err := yaml.NewDecoder(resp.Body).Decode(&index); err != nil {
		t.Fatalf("failed to decode helm index: %v", err)
	}
	if len(index.Entries) == 0 {
		t.Fatalf("helm index is empty")
	}

	for _, chartName := range utils.AllReleaseCharts() {
		t.Run(chartName, func(t *testing.T) {
			chartEntries, ok := index.Entries[chartName]
			if !ok || len(chartEntries) == 0 {
				t.Fatalf("helm index does not contain %s entries", chartName)
			}
			filteredEntries := slices.Collect(func(yield func(map[string]any) bool) {
				for _, entry := range chartEntries {
					if entry["version"].(string) == releaseVersion {
						yield(entry)
					}
				}
			})
			if len(filteredEntries) == 0 {
				t.Fatalf("helm index does not contain %s entry for version %s", chartName, releaseVersion)
			} else if len(filteredEntries) > 1 {
				t.Fatalf("helm index contains multiple %s entries for version %s", chartName, releaseVersion)
			}
			helmEntry := filteredEntries[0]
			var foundURLs []string
			if urls, ok := helmEntry["urls"]; ok || len(urls.([]any)) == 0 {
				for _, url := range urls.([]any) {
					foundURLs = append(foundURLs, url.(string))
				}
			} else {
				t.Fatalf("helm index entry for chart %s version %s does not contain urls", chartName, releaseVersion)
			}

			chartURLs := chartURLs(githubOrg, githubRepo, releaseVersion)
			if chartURL, ok := chartURLs[chartName]; ok {
				if !slices.Contains(foundURLs, chartURL) {
					t.Fatalf("helm index entry for chart %s version %s does not contain expected URL %s", chartName, releaseVersion, chartURL)
				}
			} else {
				t.Fatalf("could not find expected chart URL for chart %s version %s", chartName, releaseVersion)
			}

		})
	}

}
