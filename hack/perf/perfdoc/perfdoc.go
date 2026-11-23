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

// Package perfdoc writes hack/perf documents from Go benchmarks: one JSON file per measurement
// under <dir>/<family>/<name>.json, which send-perf-results pushes to the Lens trend store. See
// hack/perf/README.md for the contract and the schema advice.
package perfdoc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Recorder measures a benchmark's timed loop. Start it immediately before b.ResetTimer() and
// Finish it immediately after b.StopTimer().
type Recorder struct {
	b         testing.TB
	n         func() int
	startWall time.Time
	startMem  runtime.MemStats
}

// Start begins a measurement of b's timed loop.
func Start(b *testing.B) *Recorder {
	return start(b, func() int { return b.N })
}

func start(tb testing.TB, n func() int) *Recorder {
	r := &Recorder{b: tb, n: n, startWall: time.Now()}
	runtime.ReadMemStats(&r.startMem)
	return r
}

// Finish computes the per-op wall time, bytes and allocations since Start and merges in the
// caller's scenario fields, which win over the measured ones. When dir is not empty it also writes
// the document. A failed write is logged, not fatal: the trend store is observability, not a
// critical path.
func (r *Recorder) Finish(dir, family, name string, fields map[string]any) map[string]any {
	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)
	n := r.n()
	doc := map[string]any{
		"wall_ns_per_op": float64(time.Since(r.startWall).Nanoseconds()) / float64(n),
		"bytes_per_op":   float64(endMem.TotalAlloc-r.startMem.TotalAlloc) / float64(n),
		"allocs_per_op":  float64(endMem.Mallocs-r.startMem.Mallocs) / float64(n),
		"iterations":     n,
		"ok":             true,
	}
	for k, v := range fields {
		doc[k] = v
	}
	if dir == "" {
		return doc
	}
	if err := Write(dir, family, name, doc); err != nil {
		r.b.Logf("perf: %v", err)
	}
	return doc
}

// Write writes one document to <dir>/<family>/<name>.json, creating the family directory. A
// benchmark's name has slashes between its levels; they become underscores, so each case is one
// file in the family directory.
func Write(dir, family, name string, doc map[string]any) error {
	familyDir := filepath.Join(dir, family)
	if err := os.MkdirAll(familyDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", familyDir, err)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling %s: %w", name, err)
	}
	path := filepath.Join(familyDir, strings.ReplaceAll(name, "/", "_")+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
