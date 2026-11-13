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

package cilanes

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/e2e/pkg/testconfig"
)

// AuditLane dry-runs the e2e binary for the lane's selection and works out
// which specs it runs and which it drops. It runs the binary twice: once with
// the lane's configs for the specs that run, and once with only the suites'
// include rules for the specs they select. The difference is the drop list,
// and each drop is explained from the configs.
func AuditLane(binary, repoRoot string, l Lane) (Audit, error) {
	paths, err := l.ConfigPaths(repoRoot)
	if err != nil {
		return Audit{}, err
	}
	cfg, err := testconfig.LoadAll(paths)
	if err != nil {
		return Audit{}, err
	}
	dropper, err := testconfig.NewDropper(cfg)
	if err != nil {
		return Audit{}, err
	}
	includeFlags, err := includeOnlyArgs(cfg)
	if err != nil {
		return Audit{}, err
	}
	args, err := l.SelectionArgs(repoRoot)
	if err != nil {
		return Audit{}, err
	}

	runs, err := dryRun(binary, repoRoot, args)
	if err != nil {
		return Audit{}, err
	}
	selected, err := dryRun(binary, repoRoot, includeFlags)
	if err != nil {
		return Audit{}, err
	}
	return AuditSelection(selected, runs, dropper)
}

// includeOnlyArgs returns the binary arguments that select what the suites
// select and nothing more, with no capability, upstream or quarantine filter.
func includeOnlyArgs(cfg *testconfig.Config) ([]string, error) {
	flags, err := testconfig.ToFlags(cfg.IncludeOnly())
	if err != nil {
		return nil, err
	}
	var args []string
	if flags.LabelFilter != "" {
		args = append(args, "--ginkgo.label-filter="+flags.LabelFilter)
	}
	if focus := flags.FocusString(); focus != "" {
		args = append(args, "--ginkgo.focus="+focus)
	}
	return args, nil
}

// ginkgoReport is the subset of ginkgo's JSON report that names the specs a run
// would execute and the labels they carry.
type ginkgoReport struct {
	SuiteDescription string       `json:"SuiteDescription"`
	SuiteLabels      []string     `json:"SuiteLabels"`
	SpecReports      []specReport `json:"SpecReports"`
}

// specReport is one spec in a ginkgoReport.
type specReport struct {
	ContainerHierarchyTexts  []string   `json:"ContainerHierarchyTexts"`
	ContainerHierarchyLabels [][]string `json:"ContainerHierarchyLabels"`
	LeafNodeText             string     `json:"LeafNodeText"`
	LeafNodeLabels           []string   `json:"LeafNodeLabels"`
	LeafNodeType             string     `json:"LeafNodeType"`
	State                    string     `json:"State"`
}

// dryRun returns the specs a selection would run, sorted by text. A dry run
// passes selected specs and skips filtered ones.
func dryRun(binary, workDir string, args []string) ([]testconfig.Spec, error) {
	// Run the binary in dry-run mode, which writes a JSON report of every spec.
	report, err := os.CreateTemp("", "gen-test-set-*.json")
	if err != nil {
		return nil, err
	}
	if err := report.Close(); err != nil {
		return nil, err
	}
	defer func() {
		if err := os.Remove(report.Name()); err != nil {
			logrus.WithError(err).Warn("Failed to remove the dry-run report")
		}
	}()

	cmd := exec.Command(binary, append([]string{
		"--ginkgo.dry-run",
		"--ginkgo.json-report=" + report.Name(),
	}, args...)...)
	cmd.Dir = workDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, out)
	}

	// Keep the specs ginkgo marks as passed, which a dry run uses for selected ones.
	data, err := os.ReadFile(report.Name())
	if err != nil {
		return nil, err
	}
	var suites []ginkgoReport
	if err := json.Unmarshal(data, &suites); err != nil {
		return nil, err
	}

	var specs []testconfig.Spec
	for _, suite := range suites {
		for _, spec := range suite.SpecReports {
			if spec.LeafNodeType != "It" || spec.State != "passed" {
				continue
			}
			specs = append(specs, specOf(suite, spec))
		}
	}
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].Text < specs[j].Text })
	return specs, nil
}

// specOf builds the spec selection sees from one entry of a report. Ginkgo
// matches label filters against the suite's labels too.
func specOf(suite ginkgoReport, spec specReport) testconfig.Spec {
	parts := append(slices.Clone(spec.ContainerHierarchyTexts), spec.LeafNodeText)
	labels := slices.Clone(suite.SuiteLabels)
	for _, ls := range spec.ContainerHierarchyLabels {
		labels = append(labels, ls...)
	}
	return testconfig.Spec{
		Suite:  suite.SuiteDescription,
		Text:   strings.Join(parts, " "),
		Labels: append(labels, spec.LeafNodeLabels...),
	}
}
