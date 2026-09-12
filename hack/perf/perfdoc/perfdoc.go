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

// Package perfdoc writes hack/perf documents from Go benchmarks: one JSON file per measurement
// under <dir>/<family>/<name>.json, which send-perf-results pushes to the Lens trend store.
// See hack/perf/README.md for the contract and the schema advice.
package perfdoc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Dir returns the artifacts directory named by the environment variable, or "" when perf docs
// are off, which is the default outside CI.
func Dir(envVar string) string {
	return os.Getenv(envVar)
}

// Recorder measures a benchmark's timed loop. Start it immediately before b.ResetTimer() and
// Finish it immediately after b.StopTimer().
type Recorder struct {
	b         *testing.B
	startWall time.Time
	startMem  runtime.MemStats
}

// Start begins a measurement.
func Start(b *testing.B) *Recorder {
	r := &Recorder{b: b, startWall: time.Now()}
	runtime.ReadMemStats(&r.startMem)
	return r
}

// Finish computes the per-op wall time, bytes and allocations since Start, merges them with the
// caller's scenario fields, and, when dir is not empty, writes the document. It returns the
// document either way. A failure to write is logged through the benchmark and not fatal: the
// trend store is observability, not a critical path.
func (r *Recorder) Finish(dir, family, name string, fields map[string]any) map[string]any {
	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)
	n := float64(r.b.N)
	doc := map[string]any{
		"wall_ns_per_op": float64(time.Since(r.startWall).Nanoseconds()) / n,
		"bytes_per_op":   float64(endMem.TotalAlloc-r.startMem.TotalAlloc) / n,
		"allocs_per_op":  float64(endMem.Mallocs-r.startMem.Mallocs) / n,
		"iterations":     r.b.N,
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

// Write writes one document to <dir>/<family>/<name>.json, creating the family directory.
func Write(dir, family, name string, doc map[string]any) error {
	familyDir := filepath.Join(dir, family)
	if err := os.MkdirAll(familyDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", familyDir, err)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling %s: %w", name, err)
	}
	path := filepath.Join(familyDir, name+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
