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

type HelmIndex struct {
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

func (hi HelmIndex) CheckVersionIsPublished(version string) bool {
	for _, operator := range hi.Entries.TigeraOperator {
		if operator.AppVersion == version {
			return true
		}
	}
	return false
}

var helmChartUrl = "https://projectcalico.docs.tigera.io/charts/index.yaml"
var operatorBundleUrl = "https://github.com/projectcalico/calico/releases/download/%s/tigera-operator-%s.tgz"

func GetHelmIndex() (HelmIndex, error) {
	chartIndex := HelmIndex{}

	buf := &bytes.Buffer{}

	resp, err := http.Get(helmChartUrl)
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

func CheckLatestHelmIndex(version string) error {
	chartIndex, err := GetHelmIndex()
	if err != nil {
		panic(err)
	}

	operatorUrl := chartIndex.Entries.TigeraOperator[0].Urls[0]

	targetOperatorUrl := fmt.Sprintf(operatorBundleUrl, version, version)

	if operatorUrl != targetOperatorUrl {
		return fmt.Errorf("chart URL %s does not match expected url %s", operatorUrl, targetOperatorUrl)
	}
	return nil
}

func LoadHelmArchiveForVersion(version string) error {
	targetOperatorUrl := fmt.Sprintf(operatorBundleUrl, version, version)

	resp, err := http.Get(targetOperatorUrl)
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
		if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
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
