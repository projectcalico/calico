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

// send-perf-results scans a directory of per-test JSON measurement files,
// augments each with CI metadata, and POSTs them to the Lens Elasticsearch
// cluster.  See hack/perf/README.md for the convention.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// Field names injected into every doc unless the producer already
	// supplied them.  Keep in sync with hack/perf/README.md.
	fieldTimestamp   = "@timestamp"
	fieldGitCommit   = "git_commit"
	fieldGitBranch   = "git_branch"
	fieldCodeVersion = "code_version"
	fieldCIRunID     = "ci_run_id"
	fieldPRNumber    = "pr_number"
	fieldEnv         = "env"
)

func main() {
	dir := flag.String("dir", "artifacts/perf", "Directory to scan for per-family subdirectories of JSON docs.")
	tmplDir := flag.String("templates", "hack/perf/index-templates", "Directory containing one <family>.json template per index family.")
	dryRun := flag.Bool("dry-run", false, "Parse and augment but do not POST.  Prints each doc to stdout.")
	requireCreds := flag.Bool("require-creds", false, "Exit non-zero if Elasticsearch credentials are not configured.")
	flag.Parse()

	esURL := os.Getenv("ELASTICSEARCH_URL")
	auth, authOK := buildAuthHeader()
	if esURL == "" || !authOK {
		// "Lens is observability, not a critical path" -- see
		// hack/perf/README.md.  Missing creds in a local dev run is normal;
		// in CI it usually means the pipeline secret wasn't attached, which
		// a --require-creds caller can turn into a hard failure.
		msg := "ELASTICSEARCH_URL or credentials unset; skipping send"
		if *requireCreds {
			log.Fatalf("%s (--require-creds set)", msg)
		}
		log.Printf("%s", msg)
		if *dryRun {
			// Continue so the dry-run prints can still be useful.
		} else {
			return
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	metadata := ciMetadata()

	// Apply index templates first.  ES treats PUT _index_template/<name>
	// as an upsert, so committing template changes auto-propagates the next
	// time the tool runs.  Failures here are warnings -- a missing template
	// means new fields will get default mappings, which is a Kibana
	// inconvenience, not a data-loss event.
	if !*dryRun {
		if err := applyTemplates(client, esURL, auth, *tmplDir); err != nil {
			log.Printf("warning: applying templates failed: %v", err)
		}
	}

	if err := walkAndSend(client, esURL, auth, *dir, metadata, *dryRun); err != nil {
		// Observability failures should not propagate into CI (see README).
		log.Printf("warning: walkAndSend returned an error: %v", err)
	}
}

// buildAuthHeader returns the value for the Authorization header constructed
// from environment variables, plus a bool reporting whether credentials are
// configured at all.  Prefers an API key over basic auth.
func buildAuthHeader() (string, bool) {
	if key := os.Getenv("ELASTICSEARCH_KEY"); key != "" {
		return "ApiKey " + key, true
	}
	user := os.Getenv("ELASTICSEARCH_USER")
	token := os.Getenv("ELASTICSEARCH_TOKEN")
	if user != "" && token != "" {
		return basicAuthHeader(user, token), true
	}
	return "", false
}

// basicAuthHeader assembles a Basic auth header value the same way
// net/http does in (*Request).SetBasicAuth, without importing encoding/base64
// directly.
func basicAuthHeader(user, password string) string {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.SetBasicAuth(user, password)
	return r.Header.Get("Authorization")
}

// ciMetadata gathers the fields the tool injects into every doc whose
// producer hasn't already set them.
func ciMetadata() map[string]any {
	sha := os.Getenv("SEMAPHORE_GIT_SHA")
	codeVer := sha
	if len(codeVer) > 12 {
		codeVer = codeVer[:12]
	}
	env := "dev"
	if os.Getenv("SEMAPHORE_JOB_ID") != "" {
		env = "ci"
	}
	m := map[string]any{
		fieldTimestamp:   time.Now().UTC().Format(time.RFC3339),
		fieldGitCommit:   sha,
		fieldGitBranch:   os.Getenv("SEMAPHORE_GIT_BRANCH"),
		fieldCodeVersion: codeVer,
		fieldCIRunID:     os.Getenv("SEMAPHORE_JOB_ID"),
		fieldEnv:         env,
	}
	if pr := os.Getenv("SEMAPHORE_GIT_PR_NUMBER"); pr != "" {
		m[fieldPRNumber] = pr
	}
	return m
}

// applyTemplates PUTs each <family>.json in tmplDir to ES at
// /_index_template/<family>.
func applyTemplates(client *http.Client, esURL, auth, tmplDir string) error {
	entries, err := os.ReadDir(tmplDir)
	if err != nil {
		// A missing templates directory is not fatal: a deployment might
		// rely entirely on dynamic mapping inference.  Just warn.
		if os.IsNotExist(err) {
			log.Printf("templates directory %s does not exist; no templates applied", tmplDir)
			return nil
		}
		return fmt.Errorf("read templates dir %s: %w", tmplDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		family := strings.TrimSuffix(e.Name(), ".json")
		path := filepath.Join(tmplDir, e.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			log.Printf("warning: read %s: %v", path, err)
			continue
		}
		endpoint := fmt.Sprintf("%s/_index_template/%s", strings.TrimRight(esURL, "/"), url.PathEscape(family))
		if err := esRequest(client, "PUT", endpoint, auth, body); err != nil {
			log.Printf("warning: PUT template %s: %v", family, err)
			continue
		}
		log.Printf("applied template %s", family)
	}
	return nil
}

// walkAndSend processes every <dir>/<family>/*.json file, augmenting and
// POSTing to <family>_<UTC year>.
func walkAndSend(client *http.Client, esURL, auth, dir string, metadata map[string]any, dryRun bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("perf-results directory %s does not exist; nothing to send", dir)
			return nil
		}
		return fmt.Errorf("read dir %s: %w", dir, err)
	}
	year := time.Now().UTC().Format("2006")
	for _, e := range entries {
		if !e.IsDir() {
			// Stray files at the top level are not part of the convention.
			// Warn and skip rather than silently dropping; that way a
			// producer that writes to the wrong place gets a visible cue.
			log.Printf("warning: skipping %s (not a family subdirectory)", e.Name())
			continue
		}
		family := e.Name()
		familyDir := filepath.Join(dir, family)
		sent, failed, err := sendFamily(client, esURL, auth, familyDir, family, year, metadata, dryRun)
		if err != nil {
			log.Printf("warning: family %s: %v", family, err)
		}
		log.Printf("family %s: sent %d, failed %d", family, sent, failed)
	}
	return nil
}

// sendFamily handles one <family> subdirectory: walks all *.json under it,
// augments with metadata, and POSTs to <family>_<year>.
func sendFamily(client *http.Client, esURL, auth, familyDir, family, year string, metadata map[string]any, dryRun bool) (sent, failed int, err error) {
	files, err := filepath.Glob(filepath.Join(familyDir, "*.json"))
	if err != nil {
		return 0, 0, fmt.Errorf("glob %s: %w", familyDir, err)
	}
	endpoint := fmt.Sprintf("%s/%s_%s/_doc",
		strings.TrimRight(esURL, "/"),
		url.PathEscape(family),
		year,
	)
	for _, f := range files {
		raw, rerr := os.ReadFile(f)
		if rerr != nil {
			log.Printf("warning: read %s: %v", f, rerr)
			failed++
			continue
		}
		var doc map[string]any
		if jerr := json.Unmarshal(raw, &doc); jerr != nil {
			log.Printf("warning: parse %s: %v", f, jerr)
			failed++
			continue
		}
		// Producer-supplied values win.  Inject only what isn't already set.
		for k, v := range metadata {
			if _, present := doc[k]; !present {
				doc[k] = v
			}
		}
		body, _ := json.Marshal(doc)
		if dryRun {
			log.Printf("dry-run: would POST %s\n  %s", endpoint, string(body))
			sent++
			continue
		}
		if perr := esRequest(client, "POST", endpoint, auth, body); perr != nil {
			log.Printf("warning: POST %s (%s): %v", f, family, perr)
			failed++
			continue
		}
		sent++
	}
	return sent, failed, nil
}

// esRequest performs a single HTTP request to ES with the given method,
// endpoint, auth header, and JSON body.  Returns an error on transport
// failure or any non-2xx response.
func esRequest(client *http.Client, method, endpoint, auth string, body []byte) error {
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, endpoint, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
