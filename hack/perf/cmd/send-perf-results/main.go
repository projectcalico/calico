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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
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
	requirePublication := flag.Bool("require-publication", false, "Exit non-zero unless every document found was published.")
	flag.Parse()

	esURL := os.Getenv("ELASTICSEARCH_URL")
	auth, authOK := buildAuthHeader()
	if esURL == "" || !authOK {
		// "Lens is observability, not a critical path" -- see
		// hack/perf/README.md.  Missing creds in a local dev run is normal;
		// in CI it usually means the pipeline secret wasn't attached, which
		// a --require-publication caller can turn into a hard failure.
		msg := "ELASTICSEARCH_URL or credentials unset; skipping send"
		if *requirePublication {
			log.Fatalf("%s (--require-publication set)", msg)
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

	sent, failed, err := publish(client, esURL, auth, *dir, *tmplDir, metadata, *dryRun)
	if err != nil {
		// Observability failures should not propagate into CI (see README) --
		// except for a caller that exists to publish, where a green run that
		// published nothing is the worse outcome.  Same reasoning as the
		// missing-credentials case above, and the same flag governs both.
		if *requirePublication {
			log.Fatalf("send failed: %v (--require-publication set)", err)
		}
		log.Printf("warning: walkAndSend returned an error: %v", err)
		return
	}
	// The counts, not the returned error, are what catch the likely failures
	// here: a rejected credential fails each POST separately and walkAndSend
	// logs those as warnings, so it still returns nil.  Having nothing to send
	// is equally wrong for a caller whose output is the documents.
	if *requirePublication {
		switch {
		case sent == 0 && failed == 0:
			log.Fatalf("found no documents to publish under %s (--require-publication set)", *dir)
		case failed > 0:
			log.Fatalf("published %d of %d documents, %d failed (--require-publication set)", sent, sent+failed, failed)
		}
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

// firstEnv returns the first of names that is set to a non-empty value.
// It lets the CI-provenance fields below be filled from whichever CI system
// is running us, without the caller caring which.
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// ciMetadata gathers the fields the tool injects into every doc whose
// producer hasn't already set them.
//
// Provenance comes from whichever CI system is running us: Semaphore exports
// SEMAPHORE_*, ArgoCI exports CI_GIT_*.  Reading both means a test moved
// between them keeps landing complete documents, rather than silently
// recording blank git_commit/git_branch and an env of "dev" -- which would be
// indistinguishable from a developer's laptop run and would pollute the trend
// data (see hack/perf/README.md).
//
// env defaults to "dev", becomes "ci" when a recognised CI run ID is present,
// and can be set explicitly with PERF_ENV.  Scheduled runs should set
// PERF_ENV so their results can be told apart from per-PR ones -- they may
// use different machine types, so their timings are not comparable.
func ciMetadata() map[string]any {
	sha := firstEnv("SEMAPHORE_GIT_SHA", "CI_GIT_SHA")
	codeVer := sha
	if len(codeVer) > 12 {
		codeVer = codeVer[:12]
	}
	runID := firstEnv("SEMAPHORE_JOB_ID", "CI_JOB_ID", "CI_WORKFLOW_NAME")
	env := "dev"
	if runID != "" {
		env = "ci"
	}
	if e := os.Getenv("PERF_ENV"); e != "" {
		env = e
	}
	m := map[string]any{
		fieldTimestamp:   time.Now().UTC().Format(time.RFC3339),
		fieldGitCommit:   sha,
		fieldGitBranch:   firstEnv("SEMAPHORE_GIT_BRANCH", "CI_GIT_BRANCH"),
		fieldCodeVersion: codeVer,
		fieldCIRunID:     runID,
		fieldEnv:         env,
	}
	if pr := firstEnv("SEMAPHORE_GIT_PR_NUMBER", "CI_GIT_PR_NUMBER"); pr != "" && pr != "none" {
		m[fieldPRNumber] = pr
	}
	return m
}

// publish applies the index templates and sends every document under dir, returning the
// totals from walkAndSend.
//
// A PR run must not change the schema: a field's type is fixed once it is first mapped, and a
// PR is still being iterated on.  So a PR run leaves templates and mappings alone, and holds
// back any field the live index has not mapped yet.  The first run after merge applies the
// reviewed template and publishes the new fields.
func publish(client *http.Client, esURL, auth, dir, tmplDir string, metadata map[string]any, dryRun bool) (int, int, error) {
	_, prRun := metadata[fieldPRNumber]
	year := indexYear()
	var fields fieldFilter
	switch {
	case dryRun:
	case prRun:
		log.Printf("PR run: leaving index templates and mappings unchanged")
		fields = func(family string) (set.Set[string], error) {
			return mappedFields(client, esURL, auth, family, year)
		}
	default:
		// Failures here are warnings -- a missing mapping means new fields get default
		// mappings, which is a Kibana inconvenience, not a data-loss event.
		if err := applyTemplates(client, esURL, auth, tmplDir, year); err != nil {
			log.Printf("warning: applying templates failed: %v", err)
		}
	}
	return walkAndSend(client, esURL, auth, dir, year, metadata, fields, dryRun)
}

// fieldFilter returns the set of fields a family's documents may carry, or nil for no limit.
type fieldFilter func(family string) (set.Set[string], error)

// errIndexNotCreated means the year's index does not exist yet.  A PR run must not create it:
// it would be built from whatever template ES holds, and any field that template lacks would
// then be mapped by inference.
var errIndexNotCreated = errors.New("index not created yet")

// mappedFields returns the top-level fields that the family's index for year has mapped, or
// errIndexNotCreated.
func mappedFields(client *http.Client, esURL, auth, family, year string) (set.Set[string], error) {
	index := family + "_" + year
	endpoint := fmt.Sprintf("%s/%s/_mapping", strings.TrimRight(esURL, "/"), url.PathEscape(index))
	body, err := esGet(client, endpoint, auth)
	var httpErr *esHTTPError
	if errors.As(err, &httpErr) && httpErr.status == http.StatusNotFound {
		return nil, errIndexNotCreated
	} else if err != nil {
		return nil, err
	}
	// Keyed by concrete index name, which differs from the one asked for if that is an alias.
	var resp map[string]struct {
		Mappings struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse mapping of %s: %w", index, err)
	}
	fields := set.New[string]()
	for _, idx := range resp {
		for name := range idx.Mappings.Properties {
			fields.Add(name)
		}
	}
	return fields, nil
}

// applyTemplates PUTs each <family>.json in tmplDir to ES at /_index_template/<family>, and its
// mappings to the live <family>_<year> index.
//
// A template only shapes an index when the index is created, but fields are added part-way through
// a year.  Without the live-index PUT, a new field's first document would fix its type by inference
// -- a string becomes text plus .keyword -- and next year's index, built from the template, would
// disagree with this year's.
func applyTemplates(client *http.Client, esURL, auth, tmplDir, year string) error {
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
		} else {
			log.Printf("applied template %s", family)
		}

		// Independent of the template PUT: putting a template needs a cluster privilege
		// that a writer of documents may lack, while extending an index's mapping is an
		// index privilege.
		applyLiveMapping(client, esURL, auth, family, year, body)
	}
	return nil
}

// applyLiveMapping PUTs the mappings from a template body to the family's index for year.  Adding
// a field is allowed on a live index; changing an existing field's type is not, and ES rejects the
// whole PUT, which is logged here as a warning.
func applyLiveMapping(client *http.Client, esURL, auth, family, year string, templateBody []byte) {
	var tmpl struct {
		Template struct {
			Mappings json.RawMessage `json:"mappings"`
		} `json:"template"`
	}
	if err := json.Unmarshal(templateBody, &tmpl); err != nil {
		log.Printf("warning: parse template %s: %v", family, err)
		return
	}
	if len(tmpl.Template.Mappings) == 0 {
		return
	}
	index := family + "_" + year
	endpoint := fmt.Sprintf("%s/%s/_mapping", strings.TrimRight(esURL, "/"), url.PathEscape(index))
	err := esRequest(client, "PUT", endpoint, auth, tmpl.Template.Mappings)
	var httpErr *esHTTPError
	switch {
	case err == nil:
		log.Printf("applied mappings to %s", index)
	case errors.As(err, &httpErr) && httpErr.status == http.StatusNotFound:
		// The year's first document will create the index from the template.
		log.Printf("index %s does not exist yet; it will be created from the template", index)
	default:
		log.Printf("warning: PUT mappings to %s: %v", index, err)
	}
}

// indexYear is the suffix of the indices this run writes to.
func indexYear() string {
	return time.Now().UTC().Format("2006")
}

// walkAndSend processes every <dir>/<family>/*.json file, augmenting and
// POSTing to <family>_<UTC year>.  It returns the totals across all families
// as well as an error: everything short of "the directory could not be read"
// is a warning here, so a caller gating on the outcome has to read the counts.
func walkAndSend(client *http.Client, esURL, auth, dir, year string, metadata map[string]any, fields fieldFilter, dryRun bool) (int, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("perf-results directory %s does not exist; nothing to send", dir)
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("read dir %s: %w", dir, err)
	}
	totalSent, totalFailed := 0, 0
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
		var allowed set.Set[string]
		if fields != nil {
			var aerr error
			allowed, aerr = fields(family)
			if errors.Is(aerr, errIndexNotCreated) {
				log.Printf("family %s: not sent, %s_%s is not created yet; a run after merge creates it", family, family, year)
				continue
			} else if aerr != nil {
				// Sending without knowing what is mapped could add fields to the
				// schema.
				log.Printf("warning: family %s: not sent, could not tell which fields are mapped: %v", family, aerr)
				totalFailed++
				continue
			}
		}
		sent, failed, ferr := sendFamily(client, esURL, auth, familyDir, family, year, metadata, allowed, dryRun)
		if ferr != nil {
			log.Printf("warning: family %s: %v", family, ferr)
			// A family that could not be walked published nothing, and has no
			// per-document failures to show for it.  Count one so the totals
			// cannot report a clean run.
			failed++
		}
		log.Printf("family %s: sent %d, failed %d", family, sent, failed)
		totalSent += sent
		totalFailed += failed
	}
	return totalSent, totalFailed, nil
}

// sendFamily handles one <family> subdirectory: walks all *.json under it,
// augments with metadata, and POSTs to <family>_<year>.  A non-nil allowed
// drops every field not in it.
func sendFamily(client *http.Client, esURL, auth, familyDir, family, year string, metadata map[string]any, allowed set.Set[string], dryRun bool) (sent, failed int, err error) {
	files, err := filepath.Glob(filepath.Join(familyDir, "*.json"))
	if err != nil {
		return 0, 0, fmt.Errorf("glob %s: %w", familyDir, err)
	}
	endpoint := fmt.Sprintf("%s/%s_%s/_doc",
		strings.TrimRight(esURL, "/"),
		url.PathEscape(family),
		year,
	)
	heldBack := set.New[string]()
	defer func() {
		if heldBack.Len() > 0 {
			names := heldBack.Slice()
			sort.Strings(names)
			log.Printf("family %s: held back fields not yet mapped, until a run after merge: %s", family, strings.Join(names, ", "))
		}
	}()
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
		if allowed != nil {
			for k := range doc {
				if !allowed.Contains(k) {
					delete(doc, k)
					heldBack.Add(k)
				}
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

// esHTTPError is a non-2xx response from ES.
type esHTTPError struct {
	method, endpoint string
	status           int
	body             string
}

func (e *esHTTPError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.method, e.endpoint, e.status, e.body)
}

// esRequest performs a single HTTP request to ES with the given method,
// endpoint, auth header, and JSON body.  Returns an error on transport
// failure, or an *esHTTPError on any non-2xx response.
func esRequest(client *http.Client, method, endpoint, auth string, body []byte) error {
	_, err := esDo(client, method, endpoint, auth, body)
	return err
}

// esGet is esRequest for a GET, returning the response body.
func esGet(client *http.Client, endpoint, auth string) ([]byte, error) {
	return esDo(client, "GET", endpoint, auth, nil)
}

func esDo(client *http.Client, method, endpoint, auth string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &esHTTPError{method: method, endpoint: endpoint, status: resp.StatusCode, body: strings.TrimSpace(string(respBody))}
	}
	return io.ReadAll(resp.Body)
}
