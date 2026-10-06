// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package outputs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectcalico/calico/release/internal/registry"
)

const refsFileName = "published.refs"

// An empty dir would resolve against the working directory.
var errNoRecordsDir = errors.New("no records directory specified")

// RefsWriter records published digest refs, one per line, as
// registry/repo:tag@sha256:hex.
//
// Refs are appended as they are published, so an interrupted run still records
// what reached the registry. ReadRefs drops the duplicates a resumed run adds.
type RefsWriter struct {
	mu   sync.Mutex
	path string
}

// RecordsDir holds every step's refs for one release, outside the upload
// directory so nothing recorded is published. Every run of the release shares
// it, so the id must not change between reruns.
func RecordsDir(outputDir, releaseID string) string {
	return filepath.Join(outputDir, "records", releaseID)
}

// The refs file is never truncated.
func NewRefsWriter(recordsDir, step string) (*RefsWriter, error) {
	if recordsDir == "" {
		return nil, errNoRecordsDir
	}
	dir := filepath.Join(recordsDir, step)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating refs dir: %w", err)
	}
	return &RefsWriter{path: filepath.Join(dir, refsFileName)}, nil
}

// Callers are serialised because components publish in parallel.
func (w *RefsWriter) Add(refs ...string) error {
	if len(refs) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening refs file: %w", err)
	}

	var b strings.Builder
	for _, ref := range refs {
		b.WriteString(ref)
		b.WriteString("\n")
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing refs file: %w", err)
	}
	// The record must survive a run that dies partway.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("syncing refs file: %w", err)
	}
	return f.Close()
}

// ReadRefs returns a step's refs in publish order, without duplicates. A
// missing file reports no refs and no error.
func ReadRefs(recordsDir, step string) ([]string, error) {
	if recordsDir == "" {
		return nil, errNoRecordsDir
	}
	f, err := os.Open(filepath.Join(recordsDir, step, refsFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening refs file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var refs []string
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ref := strings.TrimSpace(scanner.Text())
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading refs file: %w", err)
	}
	return refs, nil
}

func DigestSourceFor(recordsDir string, steps ...string) (registry.DigestSource, error) {
	records := make([]registry.RecordedDigests, 0, len(steps))
	for _, step := range steps {
		refs, err := ReadRefs(recordsDir, step)
		if err != nil {
			return registry.DigestSource{}, fmt.Errorf("reading %s records: %w", step, err)
		}
		records = append(records, registry.DigestsByRepo(refs))
	}
	return registry.NewDigestSource(records...), nil
}
