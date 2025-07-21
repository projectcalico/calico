// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package imagescanner

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	scanResultFileName = "image-scan-result.json"
)

// Config is the configuration for the image scanner.
type Config struct {
	// APIURL is the URL for the Image Scan Service API
	APIURL string

	// Token is the token for the Image Scan Service API
	Token string

	// Scanner is the name of the scanner to use
	Scanner string
}

func (c *Config) Valid() bool {
	return c.APIURL != "" && c.Token != "" && c.Scanner != ""
}

type scanResult struct {
	ResultsLink string `json:"results_link"`
}

// Scanner is an image scanner.
type Scanner struct {
	config Config
}

// NewScanner creates a new image scanner.
func New(cfg Config) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Scan sends a request to the image scanner to scan the given images for the given product code and stream.
func (i *Scanner) Scan(productCode string, images []string, stream string, release bool, outputDir string) error {
	if !i.config.Valid() {
		logrus.Error("Invalid image scanner configuration")
		return fmt.Errorf("invalid image scanner configuration")
	}
	var bucketPath, scanType string
	if release {
		scanType = "release"
		bucketPath = fmt.Sprintf("release/%s", stream)
	} else {
		scanType = "image"
		bucketPath = fmt.Sprintf("hashrelease/%s", stream)
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
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/iss/scan", i.config.APIURL), bytes.NewReader(marshalled))
	if err != nil {
		logrus.WithError(err).Error("Failed to create request for image scanner")
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", i.config.Token))
	req.Header.Set("Content-Type", "application/json")
	query := req.URL.Query()
	query.Add("scan_type", scanType)
	query.Add("scanner_select", i.config.Scanner)
	query.Add("project_name", productCode)
	query.Add("project_version", stream)
	if !release {
		query.Add("upload", "daily")
	}
	req.URL.RawQuery = query.Encode()
	logrus.WithFields(logrus.Fields{
		"images":      images,
		"bucket_path": bucketPath,
		"scan_type":   scanType,
		"scanner":     i.config.Scanner,
		"version":     stream,
	}).Debug("Sending image scan request")
	// Create a httpClient to skip TLS verification since ISS is an internal service.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to send request to image scanner")
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logrus.WithField("status", resp.StatusCode).Info("Image scan request sent successfully")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logrus.WithError(err).Error("Failed to read response body from image scanner")
			return err
		}
		var result scanResult
		if err := json.Unmarshal(body, &result); err != nil {
			logrus.WithError(err).Error("Failed to unmarshal image scan result")
			return fmt.Errorf("failed to unmarshal image scan result: %w", err)
		}
		logrus.WithField("results_link", result.ResultsLink).Debug("Image scan result URL retrieved")
		if result.ResultsLink == "" {
			logrus.Error("Image scan result URL is empty")
			return fmt.Errorf("image scanner returned an empty results link")
		}
		if err := writeScanResultToFile(result.ResultsLink, outputDir); err != nil {
			logrus.WithError(err).Error("Failed to write image scan result to file")
			return err
		}
		return nil
	} else if resp.StatusCode == http.StatusLocked {
		logrus.WithField("status", resp.StatusCode).Error("Image scan service is currently processing another request")
		return fmt.Errorf("image scan service is currently processing another request")
	} else if resp.StatusCode >= 500 {
		logrus.WithField("status", resp.StatusCode).Error("Image scan service is currently unavailable")
		return fmt.Errorf("image scan service is currently unavailable")
	}
	logrus.WithField("status", resp.StatusCode).Error("Unexpected response from image scanner")
	return fmt.Errorf("unexpected response from image scanner: %d", resp.StatusCode)
}

// writeScanResultToFile writes the image scan result to a file.
func writeScanResultToFile(result string, outputDir string) error {
	if outputDir == "" {
		return fmt.Errorf("output directory is not specified")
	}
	outputFilePath := filepath.Join(outputDir, scanResultFileName)
	if err := os.WriteFile(outputFilePath, []byte(result), 0o644); err != nil {
		logrus.WithError(err).Error("Failed to create image scan result file")
		return err
	}
	logrus.WithField("file", outputFilePath).Info("Image scan result written to file")
	return nil
}

// RetrieveResultURL retrieves the URL to the image scan result from the scan result file.
func RetrieveResultURL(outputDir string) (string, error) {
	if outputDir == "" {
		return "", fmt.Errorf("output directory is not specified")
	}
	outputFilePath := filepath.Join(outputDir, scanResultFileName)
	if _, err := os.Stat(outputFilePath); os.IsNotExist(err) {
		return "", fmt.Errorf("image scan result file does not exist")
	}
	resultData, err := os.ReadFile(outputFilePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to read image scan result file")
		return "", err
	}
	result := strings.TrimSpace(string(resultData))
	return result, nil
}
