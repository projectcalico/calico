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

package utils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
)

func TestSandcatSlugIsFilesystemSafeAndStable(t *testing.T) {
	s := sandcatSlug("[calico] Policy / denies (weird:chars) traffic")
	if s == "" {
		t.Fatal("empty slug")
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if !ok {
			t.Fatalf("slug has unsafe char %q in %q", r, s)
		}
	}
	if sandcatSlug("x") != sandcatSlug("x") {
		t.Fatal("slug not stable")
	}
}

func failedReport() ginkgo.SpecReport {
	return ginkgo.SpecReport{
		ContainerHierarchyTexts: []string{"[calico]", "NetworkPolicy"},
		LeafNodeText:            "denies traffic",
		State:                   types.SpecStateFailed,
		Failure:                 types.Failure{Message: "expected connection to be denied", FailureNodeType: types.NodeTypeIt},
	}
}

func TestWriteSpecResultShape(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "result.json")
	report := failedReport()
	if err := writeSpecResult(p, report.FullText(), report); err != nil {
		t.Fatal(err)
	}
	var got struct {
		TestName string `json:"test_name"`
		Passed   bool   `json:"passed"`
		Specs    []struct {
			Name            string `json:"name"`
			State           string `json:"state"`
			Failure         string `json:"failure"`
			FailureNodeType string `json:"failure_node_type"`
		} `json:"specs"`
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Passed {
		t.Fatal("passed should be false")
	}
	if len(got.Specs) != 1 {
		t.Fatalf("want 1 spec, got %d", len(got.Specs))
	}
	s := got.Specs[0]
	if s.Name != "[calico] NetworkPolicy denies traffic" {
		t.Fatalf("name: %q", s.Name)
	}
	if s.State != "failed" || s.FailureNodeType != "It" || s.Failure == "" {
		t.Fatalf("spec fields wrong: %+v", s)
	}
}

// writeFakeSandcat writes a stub that records its argv and exits 0, standing in
// for the real sandcat binary.
func writeFakeSandcat(t *testing.T, dir, argsFile string) string {
	t.Helper()
	fake := filepath.Join(dir, "fake-sandcat")
	script := "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > " + argsFile + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return fake
}

func TestRunInlineDiagnosisInvokesBinary(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	t.Setenv("SANDCAT_BIN", writeFakeSandcat(t, dir, argsFile))
	t.Setenv("SANDCAT_GEMINI_KEY", "dummy")
	t.Setenv("E2E_SANDCAT_OUT_DIR", filepath.Join(dir, "out"))
	t.Setenv("E2E_SANDCAT_SOURCE_DIR", "/src")

	report := failedReport()
	runInlineDiagnosis(context.Background(), report, "test-ns")

	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("fake sandcat was not invoked: %v", err)
	}
	args := string(b)
	for _, want := range []string{"diagnose-spec", "--result-json", "--namespace", "test-ns", "--out"} {
		if !strings.Contains(args, want) {
			t.Fatalf("expected arg %q in invocation:\n%s", want, args)
		}
	}
	slug := sandcatSlug(report.FullText())
	if _, err := os.Stat(filepath.Join(dir, "out", slug, "result.json")); err != nil {
		t.Fatalf("result.json not written for the failing spec: %v", err)
	}
}

func TestRunInlineDiagnosisNoopWithoutBinary(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDCAT_BIN", "")
	t.Setenv("SANDCAT_GEMINI_KEY", "dummy")
	t.Setenv("E2E_SANDCAT_OUT_DIR", filepath.Join(dir, "out"))

	runInlineDiagnosis(context.Background(), failedReport(), "ns")

	if entries, err := os.ReadDir(filepath.Join(dir, "out")); err == nil && len(entries) != 0 {
		t.Fatalf("expected no artifacts without SANDCAT_BIN, got %d entries", len(entries))
	}
}
