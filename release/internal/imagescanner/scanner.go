package imagescanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	scanResultFileName = "image-scan-result.json"
)

// Scanner is an image scanner.
type Scanner struct {
	// API is the URL of the image scanner API.
	API string

	// Token is the token for the image scanner API.
	Token string

	// Scanner is the name of the scanner to use.
	Scanner string
}

// NewScanner creates a new image scanner.
func New(api, token, scanner string) *Scanner {
	return &Scanner{
		API:     api,
		Token:   token,
		Scanner: scanner,
	}
}

// Scan sends a request to the image scanner to scan the given images.
// The version is the version of the release.
// The release flag indicates if the images are for a release which run image and code scans.
// The outputDir is the directory to write the scan result to. If outputDir is empty, the scan result is not written to a file.
func (i *Scanner) Scan(images []string, version string, release bool, outputDir string) error {
	var bucketPath, scanType string
	if release {
		scanType = "release"
		bucketPath = fmt.Sprintf("release/%s", version)
	} else {
		scanType = "image"
		bucketPath = fmt.Sprintf("hashrelease/%s", version)
	}
	payload := map[string]interface{}{
		"images":      images,
		"bucket_path": bucketPath,
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal payload for image scanner")
		return err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/iss/scan", i.API), bytes.NewReader(marshalled))
	if err != nil {
		logrus.WithError(err).Error("Failed to create request for image scanner")
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", i.Token))
	req.Header.Set("Content-Type", "application/json")
	query := req.URL.Query()
	query.Add("scan_type", scanType)
	query.Add("scanner_select", i.Scanner)
	query.Add("project_name", utils.ProductCode)
	query.Add("project_version", version)
	req.URL.RawQuery = query.Encode()
	logrus.WithFields(logrus.Fields{
		"images":      images,
		"bucket_path": bucketPath,
		"scan_type":   scanType,
		"scanner":     i.Scanner,
		"version":     version,
	}).Debug("Sending image scan request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to send request to image scanner")
		return err
	}
	if outputDir != "" {
		if err := writeScanResultToFile(resp, outputDir); err != nil {
			logrus.WithError(err).Error("Failed to write image scan result to file")
			return err
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		logrus.Info("Image scan request sent successfully")
		return nil
	case http.StatusLocked:
		logrus.WithField("status", resp.StatusCode).Error("Image scan service is currently processing another request")
		return fmt.Errorf("image scan service is currently processing another request")
	default:
		if resp.StatusCode >= 500 {
			logrus.WithField("status", resp.StatusCode).Error("Image scan service is currently unavailable")
			return fmt.Errorf("image scan service is currently unavailable")
		}
		logrus.WithField("status", resp.StatusCode).Error("Failed to send request to image scanner")
		return fmt.Errorf("failed to send request to image scanner")
	}
}

func writeScanResultToFile(resp *http.Response, outputDir string) error {
	defer resp.Body.Close()
	outputFilePath := filepath.Join(outputDir, scanResultFileName)
	if _, err := os.Stat(outputFilePath); err == nil {
		logrus.WithField("file", outputFilePath).Error("Image scan result file already exists")
		return fmt.Errorf("image scan result file already exists")
	}
	file, err := os.Create(outputFilePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to create image scan result file")
		return err
	}
	defer file.Close()
	if _, err := file.ReadFrom(resp.Body); err != nil {
		logrus.WithError(err).Error("Failed to write image scan result to file")
		return err
	}
	logrus.WithField("file", outputFilePath).Info("Image scan result written to file")
	return nil
}

func RetrieveResultURL(outputDir string) string {
	outputFilePath := filepath.Join(outputDir, scanResultFileName)
	var result map[string]interface{}
	resultData, err := os.ReadFile(outputFilePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to read image scan result file")
		return ""
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal image scan result")
		return ""
	}
	if link, ok := result["results_link"].(string); ok {
		return link
	}
	return ""
}
