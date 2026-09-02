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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// refsFileName is the file each step appends its published digest refs to.
const refsFileName = "published.refs"

// RefsWriter records published digest refs, one per line, as
// registry/repo@sha256:hex — the form signing tools read.
//
// Refs are appended as they are published, so an interrupted run still records
// what reached the registry. ReadRefs drops the duplicates a resumed run adds.
type RefsWriter struct {
	mu   sync.Mutex
	path string
}

// NewRefsWriter opens a step's refs file, creating its directory. The file is
// never truncated.
func NewRefsWriter(baseDir, step, version string) (*RefsWriter, error) {
	dir := filepath.Join(baseDir, step, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating refs dir: %w", err)
	}
	return &RefsWriter{path: filepath.Join(dir, refsFileName)}, nil
}

// Add appends refs, one per line. Callers are serialised because components
// publish in parallel.
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
	defer f.Close()

	var b strings.Builder
	for _, ref := range refs {
		b.WriteString(ref)
		b.WriteString("\n")
	}
	if _, err := f.WriteString(b.String()); err != nil {
		return fmt.Errorf("writing refs file: %w", err)
	}
	// The record must survive a run that dies partway.
	return f.Sync()
}

// ReadRefs returns a step's recorded refs in publish order, without duplicates.
// A missing file reports no refs and no error.
func ReadRefs(baseDir, step, version string) ([]string, error) {
	f, err := os.Open(filepath.Join(baseDir, step, version, refsFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening refs file: %w", err)
	}
	defer f.Close()

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
