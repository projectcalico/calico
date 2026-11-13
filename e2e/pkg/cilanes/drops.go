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
	"fmt"
	"sort"
	"strings"

	"github.com/projectcalico/calico/e2e/pkg/testconfig"
)

// dropSeparator splits a spec from its reason on a drop list line. A spec name
// never holds a tab, so the split is unambiguous.
const dropSeparator = "\t"

// Drop is a spec a suite selected and the lane then dropped.
type Drop struct {
	// Spec is the spec's full text, as in the lane's set file.
	Spec string

	// Reason is why the lane drops it, starting with its category: a missing
	// capability, "upstream: ", "label ", "excluded: " or "quarantine: ".
	Reason string
}

// Quarantined reports whether the spec is dropped for a quarantine.
func (d Drop) Quarantined() bool {
	return strings.HasPrefix(d.Reason, testconfig.QuarantineReasonPrefix)
}

// Audit is everything a lane's selection decides about the specs its suites
// select: which it runs, and which it drops and why.
type Audit struct {
	// Runs is the sorted full text of every spec the lane runs.
	Runs []string

	// Drops is every spec a suite selected that the lane does not run, sorted
	// by spec. Each appears once, under the first reason that drops it.
	Drops []Drop
}

// QuarantineCount returns how many specs the lane drops for a quarantine.
func (a Audit) QuarantineCount() int {
	n := 0
	for _, d := range a.Drops {
		if d.Quarantined() {
			n++
		}
	}
	return n
}

// FormatDrops renders a drop list as the committed file holds it: one line per
// drop, the spec then a tab then the reason.
func FormatDrops(drops []Drop) string {
	var b strings.Builder
	for _, d := range drops {
		b.WriteString(d.Spec + dropSeparator + d.Reason + "\n")
	}
	return b.String()
}

// AuditSelection splits the specs the suites selected into those the lane runs
// and those it drops. runs is what the binary reports for the full selection,
// and is the authority on what runs; dropper only explains the rest. It fails
// when the two disagree, which means the dropper has diverged from the binary:
// a spec the binary skips that no rule explains, or one the binary runs that
// no suite selected.
func AuditSelection(selected []testconfig.Spec, runs []testconfig.Spec, dropper *testconfig.Dropper) (Audit, error) {
	// Count by text because a spec text can repeat.
	numRunning := map[string]int{}
	for _, r := range runs {
		numRunning[r.Text]++
	}

	// Each selected spec either runs or has a rule that explains its drop.
	var audit Audit
	for _, s := range selected {
		if numRunning[s.Text] > 0 {
			numRunning[s.Text]--
			audit.Runs = append(audit.Runs, s.Text)
			continue
		}
		reason, ok := dropper.Reason(s)
		if !ok {
			return Audit{}, fmt.Errorf("the binary skips %q but no rule in the lane's configs drops it", s.Text)
		}
		audit.Drops = append(audit.Drops, Drop{Spec: s.Text, Reason: reason})
	}

	// Anything still unmatched ran without being selected.
	for text, n := range numRunning {
		if n > 0 {
			return Audit{}, fmt.Errorf("the binary runs %q but no suite of the lane selects it", text)
		}
	}

	sort.Strings(audit.Runs)
	sort.SliceStable(audit.Drops, func(i, j int) bool { return audit.Drops[i].Spec < audit.Drops[j].Spec })
	return audit, nil
}
