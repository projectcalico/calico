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

// Package parity canonicalises resolved e2e jobs for the parity harness: it
// projects a job's environment onto the test-significant variables and
// provides a stable signature so a Semaphore-derived job set and an
// ArgoCI-derived job set can be diffed. See .argoci/DESIGN.md.
package parity

import (
	"sort"
	"strings"
)

// ignore lists env var names excluded from parity comparison — infra/platform
// variables that legitimately differ between Semaphore and ArgoCI, or that do
// not affect which tests run. It mirrors the exclusion list in the existing
// .semaphore/end-to-end/report/generate_e2e_report.py so the two enumerators
// agree on what "significant" means.
var ignore = map[string]bool{
	"PRODUCT":                   true,
	"KIND_CONFIG":               true,
	"INSTALL_ETCD_POD":          true,
	"K8S_E2E_EXTRA_FLAGS":       true,
	"SEMAPHORE_ARTIFACT_EXPIRY": true,
	"NUM_INFRA_NODES":           true,
	"GOOGLE_PROJECT":            true,
	"GOOGLE_REGION":             true,
	"GOOGLE_ZONE":               true,
	"GOOGLE_NETWORK":            true,
	"VPC_SUBNETS":               true,
	"IPAM_TEST_POOL_SUBNET":     true,
}

// Significant returns a copy of env with the ignored (infra-only) variables
// removed.
func Significant(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if !ignore[k] {
			out[k] = v
		}
	}
	return out
}

// Key returns a stable signature of a job's significant environment, suitable
// for equality/multiset comparison between the two sides.
func Key(env map[string]string) string {
	sig := Significant(env)
	keys := make([]string, 0, len(sig))
	for k := range sig {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(sig[k])
		b.WriteByte('\n')
	}
	return b.String()
}

// CSV renders the jobs as a stable CSV: one column per significant variable
// (sorted), one row per job (sorted). Suitable for eyeballing or diffing
// against the Semaphore-side report.
func CSV(jobs []map[string]string) string {
	colSet := map[string]bool{}
	for _, j := range jobs {
		for k := range Significant(j) {
			colSet[k] = true
		}
	}
	cols := make([]string, 0, len(colSet))
	for k := range colSet {
		cols = append(cols, k)
	}
	sort.Strings(cols)

	rows := make([]string, 0, len(jobs))
	for _, j := range jobs {
		sig := Significant(j)
		fields := make([]string, len(cols))
		for i, c := range cols {
			fields[i] = csvField(sig[c])
		}
		rows = append(rows, strings.Join(fields, ","))
	}
	sort.Strings(rows)

	var b strings.Builder
	b.WriteString(strings.Join(cols, ","))
	b.WriteByte('\n')
	for _, r := range rows {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	return b.String()
}

// csvField quotes a value if it contains a comma, quote or newline.
func csvField(v string) string {
	if strings.ContainsAny(v, ",\"\n") {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

// Diff compares two job sets as multisets of significant-env signatures and
// returns the signatures present only in a and only in b. Empty/empty means
// the two sides enumerate an identical set of jobs.
func Diff(a, b []map[string]string) (onlyA, onlyB []string) {
	ca, cb := counts(a), counts(b)
	for k, n := range ca {
		for i := 0; i < n-cb[k]; i++ {
			onlyA = append(onlyA, k)
		}
	}
	for k, n := range cb {
		for i := 0; i < n-ca[k]; i++ {
			onlyB = append(onlyB, k)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}

func counts(jobs []map[string]string) map[string]int {
	m := make(map[string]int, len(jobs))
	for _, j := range jobs {
		m[Key(j)]++
	}
	return m
}
