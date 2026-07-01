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
	"os"
	"path/filepath"
	"testing"

	"github.com/projectcalico/calico/hack/argoci/convert"
	"github.com/projectcalico/calico/hack/argoci/parity"
)

// TestParityNftables is the core acceptance check: converting nftables.yml to
// a CronWorkflow and independently re-enumerating that cron must reproduce the
// exact same set of jobs (with the same significant params) as expanding the
// Semaphore pipeline directly.
func TestParityNftables(t *testing.T) {
	const pipe = "../../argoci/convert/testdata/nftables.yml"

	p, err := convert.LoadPipeline(pipe)
	if err != nil {
		t.Fatalf("LoadPipeline: %v", err)
	}

	// Semaphore side: expand directly.
	rjs := convert.Expand(p)
	semJobs := make([]map[string]string, len(rjs))
	for i, rj := range rjs {
		semJobs[i] = rj.Env
	}

	// Argo side: emit the cron, then re-enumerate it by parsing the YAML.
	yamlStr, todos := convert.Emit(p, convert.EmitOptions{
		Name: "e2e-nftables-master", Branch: "master", Schedule: "0 3 * * 2",
	})
	if len(todos) != 0 {
		t.Fatalf("unexpected CONVERTER-TODOs: %v", todos)
	}
	tmp := filepath.Join(t.TempDir(), "cron.yaml")
	if err := os.WriteFile(tmp, []byte(yamlStr), 0o644); err != nil {
		t.Fatalf("write cron: %v", err)
	}
	argoJobs, err := EnumerateCron(tmp)
	if err != nil {
		t.Fatalf("EnumerateCron: %v", err)
	}

	if len(semJobs) != len(argoJobs) {
		t.Errorf("job count: semaphore=%d, argo=%d", len(semJobs), len(argoJobs))
	}

	onlyS, onlyA := parity.Diff(semJobs, argoJobs)
	if len(onlyS) != 0 || len(onlyA) != 0 {
		t.Errorf("parity mismatch: %d only-in-semaphore, %d only-in-argo", len(onlyS), len(onlyA))
		for _, s := range onlyS {
			t.Logf("only in semaphore:\n%s", s)
		}
		for _, s := range onlyA {
			t.Logf("only in argo:\n%s", s)
		}
	}
}

// TestMultilineEnvValueRoundTrip guards the benchmarking/iptables case: an env
// value containing newlines (JSON blob, embedded kind config) must emit as
// valid YAML and round-trip through the enumerator unchanged.
func TestMultilineEnvValueRoundTrip(t *testing.T) {
	p := &convert.Pipeline{
		Name: "synthetic",
		GlobalJobConfig: convert.GlobalJobConfig{
			EnvVars: []convert.EnvVar{{Name: "K8S_E2E_FLAGS", Value: "--ginkgo.focus=x"}},
		},
		Blocks: []convert.Block{{
			Name: "blk",
			Task: convert.Task{Jobs: []convert.Job{{
				Name: "job",
				EnvVars: []convert.EnvVar{
					{Name: "MULTI", Value: "line1\nline2\nline3"},
					{Name: "JSONISH", Value: `[{"a":1},{"b":2}]` + "\n"},
					{Name: "PROVISIONER", Value: "gcp-kubeadm"},
				},
			}}},
		}},
	}
	out, todos := convert.Emit(p, convert.EmitOptions{Name: "e2e-synthetic", Branch: "master", Schedule: "0 0 * * 0"})
	if len(todos) != 0 {
		t.Fatalf("unexpected TODOs: %v", todos)
	}
	tmp := filepath.Join(t.TempDir(), "cron.yaml")
	if err := os.WriteFile(tmp, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	jobs, err := EnumerateCron(tmp) // fails here if the emitted YAML is invalid
	if err != nil {
		t.Fatalf("EnumerateCron (invalid YAML from multi-line value?): %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	if got := jobs[0]["MULTI"]; got != "line1\nline2\nline3" {
		t.Errorf("MULTI round-trip = %q", got)
	}
	if got := jobs[0]["JSONISH"]; got != `[{"a":1},{"b":2}]`+"\n" {
		t.Errorf("JSONISH round-trip = %q", got)
	}
}
