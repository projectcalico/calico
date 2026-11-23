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

// Package perfdoc writes hack/perf documents from Go benchmarks: one JSON file per case under
// <dir>/<family>/<name>.json, ready to publish to the Lens trend store.
package perfdoc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Recorder measures a benchmark's timed loop.
type Recorder struct {
	b        *testing.B
	startMem runtime.MemStats
}

// Start begins a measurement and resets the benchmark's timer; call it in place of
// b.ResetTimer(), right before the timed loop. It reads the allocation counters before the timer
// starts because reading them stops the world, which a loop of short ops would otherwise pay for.
func Start(b *testing.B) *Recorder {
	r := &Recorder{b: b}
	runtime.ReadMemStats(&r.startMem)
	b.ResetTimer()
	return r
}

// Finish stops the timer and computes the loop's wall time per op, from the benchmark's own timer,
// and its bytes and allocations per op. The caller's scenario fields are merged in and win over
// the measured ones. When dir is not empty it also writes the case's document: if the case runs
// several times in this process, as under -count, the document holds each numeric field's median
// over the runs, with the wall time's spread, and that is what Finish returns. A failed write is
// logged, not fatal: the trend store is observability, not a critical path.
func (r *Recorder) Finish(dir, family, name string, fields map[string]any) map[string]any {
	r.b.StopTimer()
	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)
	n := float64(r.b.N)
	doc := map[string]any{
		"wall_ns_per_op": float64(r.b.Elapsed().Nanoseconds()) / n,
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
	doc = runs.add(filepath.Join(dir, family, name), r.b.N, doc)
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

// runs holds every measurement of each case this process has taken.
var runs = caseRuns{byCase: map[string][]measurement{}}

type caseRuns struct {
	mu     sync.Mutex
	byCase map[string][]measurement
}

type measurement struct {
	n   int
	doc map[string]any
}

// add records a measurement of a case and returns the document for all of its runs so far.
func (c *caseRuns) add(key string, n int, doc map[string]any) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byCase[key] = append(c.byCase[key], measurement{n: n, doc: doc})
	return summarise(finalRuns(c.byCase[key]))
}

// finalRuns picks the measurement each run of a benchmark ended on. Every run starts by calling
// the benchmark once with b.N = 1, to size the timed runs that follow, so a measurement with
// b.N = 1 starts a new run, and the measurement before it ended the previous one.
func finalRuns(ms []measurement) []map[string]any {
	var finals []map[string]any
	for i, m := range ms {
		if i == len(ms)-1 || ms[i+1].n == 1 {
			finals = append(finals, m.doc)
		}
	}
	return finals
}

// summarise reduces the runs of a case to one document: each numeric field becomes its median,
// any other field keeps its last value, and the wall time also gets its minimum and maximum.
func summarise(docs []map[string]any) map[string]any {
	out := map[string]any{}
	values := map[string][]float64{}
	for _, d := range docs {
		for k, v := range d {
			if f, ok := number(v); ok {
				values[k] = append(values[k], f)
			} else {
				out[k] = v
			}
		}
	}
	for k, vs := range values {
		out[k] = median(vs)
	}
	if walls := values["wall_ns_per_op"]; len(walls) > 0 {
		out["wall_ns_per_op_min"] = slices.Min(walls)
		out["wall_ns_per_op_max"] = slices.Max(walls)
	}
	out["runs"] = len(docs)
	return out
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func median(vs []float64) float64 {
	s := slices.Clone(vs)
	slices.Sort(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}
