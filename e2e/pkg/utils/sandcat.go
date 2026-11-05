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

// sandcatExitMCPUnavailable is sandcat's exit code when calico-mcp cannot reach
// the cluster, which every later spec would hit too.
const sandcatExitMCPUnavailable = 3

// sandcatDisabled stops inline diagnosis for the rest of this process once
// calico-mcp is unusable.
var sandcatDisabled atomic.Bool

// registerInlineDiagnosis diagnoses a failing spec with sandcat while its
// namespace still exists: JustAfterEach runs before the spec's DeferCleanups and
// the framework's namespace deletion. Off unless SANDCAT_INLINE_DIAG is set.
func registerInlineDiagnosis(f *framework.Framework) {
	ginkgo.JustAfterEach(func(ctx ginkgo.SpecContext) {
		if os.Getenv("SANDCAT_INLINE_DIAG") == "" {
			return
		}
		report := ginkgo.CurrentSpecReport()
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

// runInlineDiagnosis passes only the spec's inputs; sandcat reads the rest from
// the environment.
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
		"--sha", os.Getenv("E2E_SANDCAT_SHA"),
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
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == sandcatExitMCPUnavailable {
			sandcatDisabled.Store(true)
			framework.Logf("[sandcat] calico-mcp is no longer usable; disabling inline diagnosis for the rest of this process")
		}
	}
}

// The JSON types below match sandcat's e2erunner.Result field tags.
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
	// The It node first: the failure site may be in a shared helper.
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

// sandcatSlug must match sandcat's signature.Slug, which names the same directory.
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
