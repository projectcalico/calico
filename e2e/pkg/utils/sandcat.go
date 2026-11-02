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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
	"k8s.io/kubernetes/test/e2e/framework"
)

// sandcatExitMCPUnavailable is sandcat's exit code for "this run cannot reach
// the cluster through calico-mcp" -- the server would not start, would not wire
// to the kubeconfig, or registered no tools. It is distinct from a generic
// failure because it describes the job rather than the spec: every later spec
// would fail the same way.
const sandcatExitMCPUnavailable = 3

// sandcatDisabled turns the inline hook off for the rest of this process once
// calico-mcp is known to be unusable.
//
// Process-scoped, because ginkgo offers nothing wider: its only cross-process
// channel is SynchronizedBeforeSuite, and the upstream k8s e2e framework already
// declares the one instance a suite may have. The job-wide cases are caught
// before the suite starts instead, by the host-side `sandcat check-mcp` probe in
// run_tests.sh; this flag only has to catch a cluster that degrades mid-run, and
// there each process learning from its own first failure is enough.
var sandcatDisabled atomic.Bool

// registerInlineDiagnosis attaches a per-spec failure hook that, when enabled,
// diagnoses a failing spec with sandcat while the cluster is still fresh — the
// failing namespace and its pods/policies still exist when sandcat inspects them.
//
// It runs in a JustAfterEach, which Ginkgo executes before every AfterEach node
// and before every DeferCleanup. That ordering matters: a test typically tears
// down its own resources with a DeferCleanup (e.g. conncheck's DeferCleanup(ct.Stop)),
// and the framework deletes the test namespace in its AfterEach. Both of those
// run after this JustAfterEach, so the failing state is still live at diagnosis
// time. The whole thing is gated on SANDCAT_INLINE_DIAG so normal and local runs
// are unaffected, and it is strictly best-effort: any error is logged, never
// propagated (the spec has already failed).
func registerInlineDiagnosis(f *framework.Framework) {
	ginkgo.JustAfterEach(func(ctx ginkgo.SpecContext) {
		if os.Getenv("SANDCAT_INLINE_DIAG") == "" {
			return
		}
		report := ginkgo.CurrentSpecReport()
		// Only genuine test-node failures are sandcat's lane. A suite abort
		// or interrupt (whole-run cancellation) is not a spec defect.
		switch report.State {
		case types.SpecStateFailed, types.SpecStatePanicked, types.SpecStateTimedout:
		default:
			return
		}
		defer func() {
			if r := recover(); r != nil {
				framework.Logf("[sandcat] inline diagnosis panicked (ignored): %v", r)
			}
		}()
		ns := ""
		if f.Namespace != nil {
			ns = f.Namespace.Name
		}
		runInlineDiagnosis(ctx, report, ns)
	})
}

// runInlineDiagnosis shells out to the sandcat binary to diagnose one failing
// spec. sandcat reads its coordination knobs (sig-dir, budget, concurrency cap,
// Gemini key, branch/PR priors) from the environment, so this only passes the
// spec-specific inputs.
func runInlineDiagnosis(ctx context.Context, report ginkgo.SpecReport, namespace string) {
	if sandcatDisabled.Load() {
		return
	}
	bin := os.Getenv("SANDCAT_BIN")
	if bin == "" {
		framework.Logf("[sandcat] SANDCAT_BIN not set; skipping inline diagnosis")
		return
	}
	if os.Getenv("SANDCAT_GEMINI_KEY") == "" && os.Getenv("GEMINI_API_KEY") == "" {
		framework.Logf("[sandcat] no Gemini API key in env; skipping inline diagnosis")
		return
	}

	specName := report.FullText()
	slug := sandcatSlug(specName)
	outBase := envOr("E2E_SANDCAT_OUT_DIR", "report/sandcat")
	outDir := filepath.Join(outBase, slug)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		framework.Logf("[sandcat] cannot create out dir %s: %v", outDir, err)
		return
	}

	resultPath := filepath.Join(outDir, "result.json")
	if err := writeSpecResult(resultPath, specName, report); err != nil {
		framework.Logf("[sandcat] cannot write result json: %v", err)
		return
	}

	kubeconfig := framework.TestContext.KubeConfig
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	args := []string{
		"diagnose-spec",
		"--result-json", resultPath,
		"--out", outDir,
		"--kubeconfig", kubeconfig,
		"--source-dir", os.Getenv("E2E_SANDCAT_SOURCE_DIR"),
		"--e2e-binary", os.Getenv("E2E_SANDCAT_E2E_BINARY"),
		"--sha", envOr("E2E_SANDCAT_SHA", os.Getenv("SEMAPHORE_GIT_SHA")),
	}
	if namespace != "" {
		args = append(args, "--namespace", namespace)
	}

	framework.Logf("[sandcat] diagnosing failed spec %q -> %s", specName, outDir)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = ginkgo.GinkgoWriter
	cmd.Stderr = ginkgo.GinkgoWriter
	if err := cmd.Run(); err != nil {
		framework.Logf("[sandcat] diagnosis command failed (ignored): %v", err)
		// The probe passed at suite start, so this is a cluster that degraded
		// since -- often the very reason these specs are failing. Every later
		// spec in this process would fail the same way, so stop here instead of
		// spawning one doomed subprocess per remaining failure.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == sandcatExitMCPUnavailable {
			sandcatDisabled.Store(true)
			framework.Logf("[sandcat] calico-mcp is no longer usable; disabling inline diagnosis for the rest of this process")
		}
	}
}

// specResultJSON mirrors the subset of sandcat's e2erunner.Result JSON shape
// that a single-spec failure needs. Field tags match e2erunner so sandcat
// unmarshals it directly.
type codeLocationJSON struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type specResultJSON struct {
	Name            string             `json:"name"`
	State           string             `json:"state"`
	Failure         string             `json:"failure,omitempty"`
	FailureNodeType string             `json:"failure_node_type,omitempty"`
	LeafText        string             `json:"leaf_text,omitempty"`
	Locations       []codeLocationJSON `json:"locations,omitempty"`
}

type resultJSON struct {
	TestName string           `json:"test_name"`
	Passed   bool             `json:"passed"`
	Specs    []specResultJSON `json:"specs"`
}

func writeSpecResult(path, specName string, report ginkgo.SpecReport) error {
	// Carry the It-node definition and the failure site so sandcat can preload
	// the failing test's source without grepping for it. The node location comes
	// first: it names the test, whereas the failure site may be in a shared
	// helper (e.g. snat.go's checkConnection).
	var locs []codeLocationJSON
	add := func(fn string, ln int) {
		if fn == "" || ln <= 0 {
			return
		}
		for _, e := range locs {
			if e.File == fn && e.Line == ln {
				return
			}
		}
		locs = append(locs, codeLocationJSON{File: fn, Line: ln})
	}
	add(report.LeafNodeLocation.FileName, report.LeafNodeLocation.LineNumber)
	add(report.Failure.Location.FileName, report.Failure.Location.LineNumber)

	r := resultJSON{
		TestName: specName,
		Passed:   false,
		Specs: []specResultJSON{{
			Name:            specName,
			State:           report.State.String(),
			Failure:         report.Failure.Message,
			FailureNodeType: report.Failure.FailureNodeType.String(),
			LeafText:        report.LeafNodeText,
			Locations:       locs,
		}},
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

var sandcatSlugUnsafe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// sandcatSlug produces a filesystem-safe artifact directory name for a spec.
// It matches sandcat's internal signature.Slug so the directory name equals the
// slug sandcat records in the artifact (and references from a dedup skip).
func sandcatSlug(specName string) string {
	base := sandcatSlugUnsafe.ReplaceAllString(strings.TrimSpace(specName), "-")
	base = strings.Trim(base, "-")
	if len(base) > 80 {
		base = base[:80]
	}
	sum := sha256.Sum256([]byte(specName))
	h := hex.EncodeToString(sum[:])[:8]
	if base == "" {
		return h
	}
	return base + "-" + h
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
