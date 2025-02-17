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
	"net/http"
	"os"
	"path/filepath"

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

// writeScanResultToFile writes the image scan result to a file.
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

// RetrieveResultURL retrieves the URL to the image scan result from the scan result file.
func RetrieveResultURL(outputDir string) (string, error) {
	outputFilePath := filepath.Join(outputDir, scanResultFileName)
	if _, err := os.Stat(outputFilePath); os.IsNotExist(err) {
		return "", fmt.Errorf("image scan result file does not exist")
	}
	var result map[string]interface{}
	resultData, err := os.ReadFile(outputFilePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to read image scan result file")
		return "", err
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal image scan result")
		return "", err
	}
	if link, ok := result["results_link"].(string); ok {
		return link, nil
	}
	return "", fmt.Errorf("no results link found in image scan result")
}
