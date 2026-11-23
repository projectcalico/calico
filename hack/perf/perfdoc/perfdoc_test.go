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

package perfdoc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFinishWritesOneDocumentPerCase(t *testing.T) {
	dir := t.TempDir()
	rec := start(t, func() int { return 4 })
	sink := make([][]byte, 0, 4)
	for range 4 {
		sink = append(sink, make([]byte, 1024))
	}
	time.Sleep(time.Millisecond)
	doc := rec.Finish(dir, "benchmark_data_example", "BenchmarkExample/Case/Variant", map[string]any{
		"test_name": "example",
		"ok":        false, // A caller's field wins over a measured one.
	})
	_ = sink

	path := filepath.Join(dir, "benchmark_data_example", "BenchmarkExample_Case_Variant.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("document not written: %v", err)
	}
	var written map[string]any
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	if written["test_name"] != "example" || written["ok"] != false {
		t.Errorf("caller's fields not kept: %v", written)
	}
	if written["iterations"] != float64(4) {
		t.Errorf("iterations = %v, want 4", written["iterations"])
	}
	if wall, _ := written["wall_ns_per_op"].(float64); wall < float64(time.Millisecond.Nanoseconds())/4 {
		t.Errorf("wall_ns_per_op = %v, want at least the 1 ms slept over 4 ops", written["wall_ns_per_op"])
	}
	if bytes, _ := written["bytes_per_op"].(float64); bytes < 1024 {
		t.Errorf("bytes_per_op = %v, want at least the 1 KiB allocated per op", written["bytes_per_op"])
	}
	if doc["test_name"] != "example" {
		t.Errorf("returned document differs from the written one: %v", doc)
	}
}

// Perf documents are off outside CI, so ordinary benchmark runs don't need a directory.
func TestFinishWithoutDirWritesNothing(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	doc := start(t, func() int { return 1 }).Finish("", "benchmark_data_example", "case", nil)
	if doc["ok"] != true {
		t.Errorf("document not returned: %v", doc)
	}
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("wrote %d entries with no directory set", len(entries))
	}
}

func TestWriteReportsAnUnwritableDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(file, "family", "case", map[string]any{}); err == nil {
		t.Error("expected an error writing under a file")
	}
}
