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

package cronreadback

import (
	"fmt"
	"sort"
	"strings"
)

// FindingKind says how a live cron differs from its file.
type FindingKind string

const (
	// MissingCron is a cron file with no live CronWorkflow.
	MissingCron FindingKind = "missing cron"

	// ExtraCron is a live CronWorkflow of the repo and branch with no file.
	ExtraCron FindingKind = "extra cron"

	// MissingCell is a cell the file declares that the live cron lacks.
	MissingCell FindingKind = "missing cell"

	// ExtraCell is a live cell with an E2E_TEST_CONFIG the file does not declare.
	ExtraCell FindingKind = "extra cell"

	// ConfigMismatch is a cell whose live E2E_TEST_CONFIG differs from the file's.
	ConfigMismatch FindingKind = "config mismatch"
)

// Finding is one difference between a merged cron file and its live cron.
type Finding struct {
	Kind FindingKind

	// Cron is the live CronWorkflow name.
	Cron string

	// Cell is the expanded step name, empty for a cron-level finding.
	Cell string

	// Want is the file's E2E_TEST_CONFIG, and Got the live one.
	Want string
	Got  string
}

// String renders the finding as one report line.
func (f Finding) String() string {
	switch f.Kind {
	case MissingCron, ExtraCron:
		return fmt.Sprintf("%s: %s", f.Kind, f.Cron)
	case MissingCell:
		return fmt.Sprintf("%s: %s / %s want %q", f.Kind, f.Cron, f.Cell, f.Want)
	case ExtraCell:
		return fmt.Sprintf("%s: %s / %s has %q", f.Kind, f.Cron, f.Cell, f.Got)
	default:
		return fmt.Sprintf("%s: %s / %s want %q, live %q", f.Kind, f.Cron, f.Cell, f.Want, f.Got)
	}
}

// LiveSet is what the read-back found in ArgoCI.
type LiveSet struct {
	// Crons holds each expected cron that exists live, by name.
	Crons map[string]LiveCron

	// Names lists every live cron of the repo on the branch, expected or not.
	Names []string
}

// Compare reports every way the live crons differ from the merged files, in a
// stable order. Configs compare by their whitespace-separated entries, because
// a file may fold a list onto several lines.
func Compare(expected []ExpectedCron, live LiveSet) []Finding {
	var findings []Finding
	known := map[string]bool{}
	for _, want := range expected {
		known[want.Name] = true
		got, ok := live.Crons[want.Name]
		if !ok {
			findings = append(findings, Finding{Kind: MissingCron, Cron: want.Name})
			continue
		}
		findings = append(findings, compareCells(want, got)...)
	}
	for _, name := range live.Names {
		if !known[name] {
			findings = append(findings, Finding{Kind: ExtraCron, Cron: name})
		}
	}
	return findings
}

// compareCells compares one cron's cells, both ways.
func compareCells(want ExpectedCron, got LiveCron) []Finding {
	var findings []Finding
	for _, cell := range sortedKeys(want.Cells) {
		wantConfig := want.Cells[cell]
		gotConfig, ok := got.Cells[cell]
		switch {
		case !ok:
			findings = append(findings, Finding{Kind: MissingCell, Cron: want.Name, Cell: cell, Want: wantConfig})
		case !sameConfig(wantConfig, gotConfig):
			findings = append(findings, Finding{Kind: ConfigMismatch, Cron: want.Name, Cell: cell, Want: wantConfig, Got: gotConfig})
		}
	}
	for _, cell := range sortedKeys(got.Cells) {
		if _, ok := want.Cells[cell]; !ok {
			findings = append(findings, Finding{Kind: ExtraCell, Cron: want.Name, Cell: cell, Got: got.Cells[cell]})
		}
	}
	return findings
}

// sameConfig reports whether two E2E_TEST_CONFIG values list the same entries
// in the same order.
func sameConfig(a, b string) bool {
	return strings.Join(strings.Fields(a), " ") == strings.Join(strings.Fields(b), " ")
}

// sortedKeys returns a map's keys in order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CellCount returns how many cells the expected crons declare.
func CellCount(expected []ExpectedCron) int {
	n := 0
	for _, c := range expected {
		n += len(c.Cells)
	}
	return n
}
