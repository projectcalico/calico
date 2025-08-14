package postrelease

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/spf13/cast"
	"go.yaml.in/yaml/v3"
	"helm.sh/helm/v3/pkg/chart/loader"
)

const helmIndexURL = "https://projectcalico.docs.tigera.io/charts/index.yaml"

func chartURL(githubOrg, githubRepo, version string) string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/tigera-operator-%s.tgz", githubOrg, githubRepo, version, version)
}

func TestHelmChart(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	resp, err := http.Get(chartURL(githubOrg, githubRepo, releaseVersion))
	if err != nil {
		t.Fatalf("failed to fetch helm chart: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to fetch helm chart: server returned %s", resp.Status)
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "*.tgz")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		t.Fatalf("failed to write helm chart to temp file: %v", err)
	}

	chart, err := loader.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load helm chart: %v", err)
	}
	if err := chart.Validate(); err != nil {
		t.Fatalf("failed to validate helm chart: %v", err)
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

	resp, err := http.Get(helmIndexURL)
	if err != nil {
		t.Fatalf("failed to fetch helm index: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to fetch helm index: server returned %s", resp.Status)
	}
	defer resp.Body.Close()
	index := helmIndex{}
	if err := yaml.NewDecoder(resp.Body).Decode(&index); err != nil {
		t.Fatalf("failed to decode helm index: %v", err)
	}
	if len(index.Entries) == 0 {
		t.Fatalf("helm index is empty")
	}
	tigeraOperatorEntries, ok := index.Entries["tigera-operator"]
	if !ok || len(tigeraOperatorEntries) == 0 {
		t.Fatalf("helm index does not contain tigera-operator entries")
	}
	filteredEntries := slices.Collect(func(yield func(map[string]any) bool) {
		for _, entry := range tigeraOperatorEntries {
			if entry["version"].(string) == releaseVersion {
				yield(entry)
			}
		}
	})
	if len(filteredEntries) == 0 {
		t.Fatalf("helm index does not contain tigera-operator entry for version %s", releaseVersion)
	} else if len(filteredEntries) > 1 {
		t.Fatalf("helm index contains multiple tigera-operator entries for version %s", releaseVersion)
	}
	helmEntry := filteredEntries[0]
	urls, ok := helmEntry["urls"]
	if !ok || len(urls.([]any)) == 0 {
		t.Fatalf("helm index entry for version %s does not contain urls", releaseVersion)
	}
	if !slices.Contains(cast.ToStringSlice(urls), chartURL(githubOrg, githubRepo, releaseVersion)) {
		t.Fatalf("helm index entry for version %s does not contain expected URL", releaseVersion)
	}
}
