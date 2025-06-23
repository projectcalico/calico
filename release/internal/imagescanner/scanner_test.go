// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/sirupsen/logrus"
)

func TestConfigValid(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectSuccess bool
	}{
		{
			name:          "valid config",
			config:        Config{APIURL: "http://example.com", Token: "token", Scanner: "scanner"},
			expectSuccess: true,
		},
		{
			name:          "missing API URL",
			config:        Config{Token: "token", Scanner: "scanner"},
			expectSuccess: false,
		},
		{
			name:          "missing token",
			config:        Config{APIURL: "http://example.com", Scanner: "scanner"},
			expectSuccess: false,
		},
		{
			name:          "missing scanner",
			config:        Config{APIURL: "http://example.com", Token: "token"},
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Valid(); got != tt.expectSuccess {
				t.Errorf("Config.Valid() = %v, want %v", got, tt.expectSuccess)
			}
		})
	}
}

func TestScannerScan(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		scanner := New(Config{})
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", false, "outputDir")
		if err == nil {
			t.Fatal("expected error for invalid config, got nil")
		}
		if err.Error() != "invalid image scanner configuration" {
			t.Errorf("expected error 'invalid image scanner configuration', got '%v'", err)
		}
	})

	t.Run("hashrelease scan", func(t *testing.T) {
		var capturedToken string
		var capturedPayload map[string]interface{}
		var capturedQuery url.Values
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedToken = r.Header.Get("Authorization")
			capturedQuery = r.URL.Query()
			if payload, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "failed to read request body", http.StatusInternalServerError)
			} else {
				if err := json.Unmarshal(payload, &capturedPayload); err != nil {
					http.Error(w, "failed to unmarshal request body", http.StatusInternalServerError)
					return
				}
			}
			defer r.Body.Close()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results_link": "http://example.com/results"}`))
		}))
		defer mockServer.Close()
		scanner := New(Config{
			APIURL:  mockServer.URL,
			Token:   "test-token",
			Scanner: "test-scanner",
		})
		tmpDir := t.TempDir()
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", false, tmpDir)
		if err != nil {
			t.Fatalf("Scan() failed: %v", err)
		}
		if capturedToken != "Bearer test-token" {
			t.Errorf("expected token 'Bearer test-token', got '%s'", capturedToken)
		}
		logrus.WithField("query", capturedQuery).Info("Captured query parameters")
		if capturedQuery.Get("scan_type") != "image" {
			t.Errorf("expected scan_type 'image', got '%s'", capturedQuery.Get("scan_type"))
		}
		if capturedQuery.Get("upload") != "daily" {
			t.Errorf("expected upload 'daily', got '%s'", capturedQuery.Get("upload"))
		}
		if path, ok := capturedPayload["bucket_path"].(string); !ok || path != "hashrelease/stream" {
			t.Errorf("expected bucket_path 'hashrelease/stream', got %q", path)
		}
	})

	t.Run("release scan", func(t *testing.T) {
		var capturedToken string
		var capturedPayload map[string]interface{}
		var capturedQuery url.Values
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedToken = r.Header.Get("Authorization")
			capturedQuery = r.URL.Query()
			if payload, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "failed to read request body", http.StatusInternalServerError)
			} else {
				if err := json.Unmarshal(payload, &capturedPayload); err != nil {
					http.Error(w, "failed to unmarshal request body", http.StatusInternalServerError)
					return
				}
			}
			defer r.Body.Close()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results_link": "http://example.com/results"}`))
		}))
		defer mockServer.Close()
		scanner := New(Config{
			APIURL:  mockServer.URL,
			Token:   "test-token",
			Scanner: "test-scanner",
		})
		tmpDir := t.TempDir()
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", true, tmpDir)
		if err != nil {
			t.Fatalf("Scan() failed: %v", err)
		}
		if capturedToken != "Bearer test-token" {
			t.Errorf("expected token 'Bearer test-token', got '%s'", capturedToken)
		}
		logrus.WithField("query", capturedQuery).Info("Captured query parameters")
		if capturedQuery.Get("scan_type") != "release" {
			t.Errorf("expected scan_type 'release', got '%s'", capturedQuery.Get("scan_type"))
		}
		if path, ok := capturedPayload["bucket_path"].(string); !ok || path != "release/stream" {
			t.Errorf("expected bucket_path 'release/stream', got %q", path)
		}
	})

	t.Run("200 series response code", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results_link": "http://example.com/results"}`))
		}))
		defer mockServer.Close()
		scanner := New(Config{
			APIURL:  mockServer.URL,
			Token:   "test-token",
			Scanner: "test-scanner",
		})
		tmpDir := t.TempDir()
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", true, tmpDir)
		if err != nil {
			t.Fatalf("Scan() failed: %v", err)
		}
	})

	t.Run("service unavailable", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer mockServer.Close()
		scanner := New(Config{
			APIURL:  mockServer.URL,
			Token:   "test-token",
			Scanner: "test-scanner",
		})
		tmpDir := t.TempDir()
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", true, tmpDir)
		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !strings.Contains(err.Error(), "currently unavailable") {
			t.Errorf("expected error to contain 'currently unavailable', got '%v'", err)
		}
	})

	t.Run("service busy", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusLocked)
		}))
		defer mockServer.Close()
		scanner := New(Config{
			APIURL:  mockServer.URL,
			Token:   "test-token",
			Scanner: "test-scanner",
		})
		tmpDir := t.TempDir()
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", true, tmpDir)
		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !strings.Contains(err.Error(), "currently processing another request") {
			t.Errorf("expected error to contain 'currently processing another request', got '%v'", err)
		}
	})

	t.Run("unexpected response", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer mockServer.Close()
		scanner := New(Config{
			APIURL:  mockServer.URL,
			Token:   "test-token",
			Scanner: "test-scanner",
		})
		tmpDir := t.TempDir()
		err := scanner.Scan("productCode", []string{"image1", "image2"}, "stream", true, tmpDir)
		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !strings.Contains(err.Error(), "unexpected response from image scanner") {
			t.Errorf("expected error to contain 'unexpected response from image scanner', got '%v'", err)
		}
	})
}

func TestWriteScanResultToFile(t *testing.T) {
	tempDir := t.TempDir()
	mockResponse := io.NopCloser(bytes.NewReader([]byte(`{"results_link": "http://example.com/results"}`)))

	if err := writeScanResultToFile(mockResponse, tempDir); err != nil {
		t.Fatalf("writeScanResultToFile() failed: %v", err)
	}

	outputFilePath := filepath.Join(tempDir, scanResultFileName)
	if _, err := os.Stat(outputFilePath); os.IsNotExist(err) {
		t.Fatalf("expected output file %q to be created", outputFilePath)
	}

	// Verify the contents of the output file
	resultData, err := os.ReadFile(outputFilePath)
	if err != nil {
		t.Fatalf("failed to read output file %q: %v", outputFilePath, err)
	}
	approvals.VerifyString(t, string(resultData))
}

func TestRetrieveResultURL(t *testing.T) {
	t.Run("no result file", func(t *testing.T) {
		tempDir := t.TempDir()
		url, err := RetrieveResultURL(tempDir)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "image scan result file does not exist" {
			t.Errorf("expected error 'image scan result file does not exist', got '%v'", err)
		}
		if url != "" {
			t.Errorf("expected empty URL, got '%s'", url)
		}
	})

	t.Run("unmarshall error", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, scanResultFileName), []byte("invalid json"), 0o644); err != nil {
			t.Fatalf("failed to write mock result file: %v", err)
		}
		url, err := RetrieveResultURL(tempDir)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal image scan result") {
			t.Errorf("expected error 'failed to unmarshal image scan result', got '%v'", err)
		}
		if url != "" {
			t.Errorf("expected empty URL, got '%s'", url)
		}
	})

	t.Run("result link", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, scanResultFileName), []byte(`{"results_link": "http://example.com/results"}`), 0o644); err != nil {
			t.Fatalf("failed to write mock result file: %v", err)
		}
		url, err := RetrieveResultURL(tempDir)
		if err != nil {
			t.Fatalf("retrieveResultURL() failed: %v", err)
		}
		if url != "http://example.com/results" {
			t.Errorf("expected URL 'http://example.com/results', got '%s'", url)
		}
	})

	t.Run("no results link", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, scanResultFileName), []byte("{}"), 0o644); err != nil {
			t.Fatalf("failed to write mock result file: %v", err)
		}
		url, err := RetrieveResultURL(tempDir)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err.Error() != "no results link found in image scan result" {
			t.Errorf("expected error 'no results link found in image scan result', got '%v'", err)
		}
		if url != "" {
			t.Errorf("expected empty URL, got '%s'", url)
		}
	})
}
