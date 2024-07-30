// Package helm contains functionality and data structures for interacting with helm charts
package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// Index represents a helm index yaml file and all of its entries
type Index struct {
	APIVersion string `yaml:"apiVersion"`
	Entries    struct {
		TigeraOperator []struct {
			APIVersion  string    `yaml:"apiVersion"`
			AppVersion  string    `yaml:"appVersion"`
			Created     time.Time `yaml:"created"`
			Description string    `yaml:"description"`
			Digest      string    `yaml:"digest"`
			Home        string    `yaml:"home"`
			Icon        string    `yaml:"icon"`
			Name        string    `yaml:"name"`
			Sources     []string  `yaml:"sources"`
			Urls        []string  `yaml:"urls"`
			Version     string    `yaml:"version"`
		} `yaml:"tigera-operator"`
	} `yaml:"entries"`
}

// CheckVersionIsPublished ensures that this Index contains the version specified
func (hi Index) CheckVersionIsPublished(version string) bool {
	for _, operator := range hi.Entries.TigeraOperator {
		if operator.AppVersion == version {
			return true
		}
	}
	return false
}

var (
	helmChartURL      = "https://projectcalico.docs.tigera.io/charts/index.yaml"
	operatorBundleURL = "https://github.com/projectcalico/calico/releases/download/%s/tigera-operator-%s.tgz"
)

// GetIndex fetches and returns the projectcalico helm chart index
func GetIndex() (Index, error) {
	chartIndex := Index{}

	buf := &bytes.Buffer{}

	resp, err := http.Get(helmChartURL)
	if err != nil {
		return chartIndex, fmt.Errorf("could not fetch helm chart: %w", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(buf.Bytes(), &chartIndex)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return chartIndex, nil
}

// LoadArchiveForVersion downloads, unpacks, and loads a helm chart from an operator tarball
func LoadArchiveForVersion(version string) error {
	targetOperatorURL := fmt.Sprintf(operatorBundleURL, version, version)

	resp, err := http.Get(targetOperatorURL)
	if err != nil {
		return fmt.Errorf("could not fetch helm chart: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to fetch helm archive: server returned %s", resp.Status)
	}

	tempDirPath, err := os.MkdirTemp("", "*-tigera-operator-helm")
	if err != nil {
		return fmt.Errorf("could not create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDirPath)

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		panic(err)
	}

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			log.Fatal(err)
		}
		fullPath := filepath.Join(tempDirPath, header.Name)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			return err
		}
		outfile, err := os.Create(fullPath)
		if err != nil {
			return err
		}
		io.Copy(outfile, tarReader)
	}

	_, err = loader.LoadDir(filepath.Join(tempDirPath, "tigera-operator"))
	if err != nil {
		return err
	}

	return nil
}
