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
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFinishWritesTheCase(t *testing.T) {
	withBenchTime(t, "4x")
	dir := t.TempDir()
	var doc map[string]any
	testing.Benchmark(func(b *testing.B) {
		rec := Start(b)
		for i := 0; i < b.N; i++ {
			sinkBytes = append(sinkBytes, make([]byte, 1024))
		}
		doc = rec.Finish(dir, "benchmark_data_example", "BenchmarkExample/Case/Variant", map[string]any{
			"test_name": "example",
			"ok":        false, // A caller's field wins over a measured one.
		})
	})

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
	if bytes, _ := written["bytes_per_op"].(float64); bytes < 1024 {
		t.Errorf("bytes_per_op = %v, want at least the 1 KiB allocated per op", written["bytes_per_op"])
	}
	if doc["test_name"] != "example" {
		t.Errorf("returned document differs from the written one: %v", doc)
	}
}

// Perf documents are off outside CI, so ordinary benchmark runs don't need a directory.
func TestFinishWithoutDirWritesNothing(t *testing.T) {
	withBenchTime(t, "1x")
	cwd := t.TempDir()
	t.Chdir(cwd)
	var doc map[string]any
	testing.Benchmark(func(b *testing.B) {
		doc = Start(b).Finish("", "benchmark_data_example", "case", nil)
	})
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

// A case run several times, as under -count, is written once: medians over the runs, the wall
// time's spread, and none of the b.N = 1 calls Go makes to size each run.
func TestRepeatedRunsAreWrittenAsMedians(t *testing.T) {
	c := caseRuns{byCase: map[string][]measurement{}}
	var doc map[string]any
	for _, wall := range []float64{10, 30, 20} {
		c.add("case", 1, map[string]any{"wall_ns_per_op": 999.0, "engine": "sizing"})
		doc = c.add("case", 20, map[string]any{"wall_ns_per_op": wall, "engine": "Interpreted"})
	}
	want := map[string]any{
		"wall_ns_per_op":     20.0,
		"wall_ns_per_op_min": 10.0,
		"wall_ns_per_op_max": 30.0,
		"engine":             "Interpreted",
		"runs":               3,
	}
	if !reflect.DeepEqual(doc, want) {
		t.Errorf("got %v, want %v", doc, want)
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

// The wall time per op must be the timed loop's alone: reading the allocation counters stops the
// world, which a loop of short ops would otherwise pay for many times over.
func TestWallTimeIsTheTimedLoopAlone(t *testing.T) {
	// A short fixed run, as CI's -benchtime 20x gives the fastest cases.
	withBenchTime(t, "20x")
	var doc map[string]any
	var elapsed time.Duration
	var n int
	testing.Benchmark(func(b *testing.B) {
		rec := Start(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sinkInt += i
		}
		b.StopTimer()
		doc = rec.Finish("", "family", "case", nil)
		elapsed, n = b.Elapsed(), b.N
	})
	want := float64(elapsed.Nanoseconds()) / float64(n)
	if got := doc["wall_ns_per_op"].(float64); got > want*1.01 {
		t.Errorf("wall_ns_per_op = %v, the timed loop took %v per op", got, want)
	}
}

var (
	sinkInt   int
	sinkBytes [][]byte
)

func withBenchTime(t *testing.T, value string) {
	f := flag.Lookup("test.benchtime")
	old := f.Value.String()
	if err := f.Value.Set(value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Value.Set(old) })
}
