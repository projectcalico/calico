// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const testTemplate = `{
  "index_patterns": ["benchmark_data_fam_*"],
  "template": {
    "mappings": {
      "properties": {
        "cpu_model": {"type": "keyword"}
      }
    }
  }
}`

type recordedRequest struct {
	method, path string
	body         []byte
}

// fakeES records every request and answers each path with the status in statuses,
// or 200 for a path it does not list.
func fakeES(t *testing.T, statuses map[string]int) (*httptest.Server, func() []recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var reqs []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, recordedRequest{r.Method, r.URL.Path, body})
		mu.Unlock()
		if code, ok := statuses[r.URL.Path]; ok {
			w.WriteHeader(code)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRequest(nil), reqs...)
	}
}

func writeTemplate(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "benchmark_data_fam.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestApplyTemplatesPutsMappingsToLiveIndex(t *testing.T) {
	// The template PUT is refused, as it is for a writer without the cluster
	// privilege; the live mapping must still be applied.
	srv, requests := fakeES(t, map[string]int{
		"/_index_template/benchmark_data_fam": http.StatusForbidden,
	})
	logs := captureLog(t)

	if err := applyTemplates(srv.Client(), srv.URL, "", writeTemplate(t, testTemplate), "2026"); err != nil {
		t.Fatal(err)
	}

	var mapping *recordedRequest
	for _, r := range requests() {
		if r.path == "/benchmark_data_fam_2026/_mapping" {
			mapping = &r
		}
	}
	if mapping == nil {
		t.Fatalf("no mapping PUT to the live index; requests: %v", requests())
	}
	if mapping.method != http.MethodPut {
		t.Errorf("mapping request method = %s, want PUT", mapping.method)
	}
	var got, want any
	if err := json.Unmarshal(mapping.body, &got); err != nil {
		t.Fatalf("mapping body is not JSON: %v", err)
	}
	_ = json.Unmarshal([]byte(`{"properties": {"cpu_model": {"type": "keyword"}}}`), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mapping body = %s, want the template's mappings", mapping.body)
	}
	if !strings.Contains(logs.String(), "applied mappings to benchmark_data_fam_2026") {
		t.Errorf("success not logged; log:\n%s", logs)
	}
}

func TestApplyTemplatesSkipsMissingIndex(t *testing.T) {
	srv, _ := fakeES(t, map[string]int{
		"/benchmark_data_fam_2026/_mapping": http.StatusNotFound,
	})
	logs := captureLog(t)

	if err := applyTemplates(srv.Client(), srv.URL, "", writeTemplate(t, testTemplate), "2026"); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(logs.String(), "warning") {
		t.Errorf("a not-yet-created index should not warn; log:\n%s", logs)
	}
	if !strings.Contains(logs.String(), "does not exist yet") {
		t.Errorf("skip not logged; log:\n%s", logs)
	}
}

func TestApplyTemplatesWarnsOnMappingConflict(t *testing.T) {
	srv, _ := fakeES(t, map[string]int{
		"/benchmark_data_fam_2026/_mapping": http.StatusBadRequest,
	})
	logs := captureLog(t)

	if err := applyTemplates(srv.Client(), srv.URL, "", writeTemplate(t, testTemplate), "2026"); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(logs.String(), "warning: PUT mappings to benchmark_data_fam_2026") {
		t.Errorf("rejected mapping not warned about; log:\n%s", logs)
	}
}

func TestApplyTemplatesWithoutMappings(t *testing.T) {
	srv, requests := fakeES(t, nil)
	captureLog(t)

	tmpl := `{"index_patterns": ["benchmark_data_fam_*"], "template": {}}`
	if err := applyTemplates(srv.Client(), srv.URL, "", writeTemplate(t, tmpl), "2026"); err != nil {
		t.Fatal(err)
	}

	for _, r := range requests() {
		if strings.HasSuffix(r.path, "/_mapping") {
			t.Errorf("unexpected mapping PUT for a template with no mappings: %s", r.path)
		}
	}
}

// A template whose mappings cannot be read would silently stop new fields reaching
// the live index.
func TestCommittedTemplatesHaveMappings(t *testing.T) {
	files, err := filepath.Glob("../../index-templates/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no committed templates found: %v", err)
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var tmpl struct {
			Template struct {
				Mappings struct {
					Properties map[string]any `json:"properties"`
				} `json:"mappings"`
			} `json:"template"`
		}
		if err := json.Unmarshal(body, &tmpl); err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(tmpl.Template.Mappings.Properties) == 0 {
			t.Errorf("%s: no template.mappings.properties", f)
		}
	}
}
