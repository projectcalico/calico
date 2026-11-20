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
)

// maxExplained caps how many specs matching a substring Explain lists.
const maxExplained = 50

// FindLane returns the set name and the lane a query names. The query is a set
// name as index.txt lists it, or a lane name when exactly one lane has it.
func FindLane(lanes []Lane, query string) (string, Lane, error) {
	sets, err := ResolveSets(lanes)
	if err != nil {
		return "", Lane{}, err
	}
	if l, ok := sets[query]; ok {
		return query, l, nil
	}

	var found []string
	for name, l := range sets {
		if l.Name == query {
			found = append(found, name)
		}
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		return "", Lane{}, fmt.Errorf("no lane has set name or lane name %q; index.txt lists them", query)
	case 1:
		return found[0], sets[found[0]], nil
	}
	return "", Lane{}, fmt.Errorf("lane name %q is in %d sets, name one of them: %s", query, len(found), strings.Join(found, ", "))
}

// Explain returns what the lane's selection does to the specs its suites
// select. With no spec it lists every drop, grouped by reason. With one it
// answers for each spec whose text contains it, ignoring case: whether the lane
// runs it, or the reason it drops it. A spec no suite of the lane selects is
// absent from both, and is reported as such.
func Explain(name string, l Lane, audit Audit, spec string) string {
	var w strings.Builder
	fmt.Fprintf(&w, "Lane %s\n", name)
	fmt.Fprintf(&w, "  %s, %s\n", l.Source, l.Name)
	fmt.Fprintf(&w, "  configs: %s\n", strings.Join(l.Configs(), " "))
	fmt.Fprintf(&w, "  runs %d specs, drops %d, %d of them quarantined\n\n", len(audit.Runs), len(audit.Drops), audit.QuarantineCount())

	if spec == "" {
		explainDrops(&w, audit.Drops)
	} else {
		explainSpec(&w, audit, spec)
	}
	return w.String()
}

// explainDrops lists the drops under their reasons, the reasons in order.
func explainDrops(w *strings.Builder, drops []Drop) {
	byReason := map[string][]string{}
	for _, d := range drops {
		byReason[d.Reason] = append(byReason[d.Reason], d.Spec)
	}
	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)

	for _, r := range reasons {
		fmt.Fprintf(w, "%s (%d)\n", r, len(byReason[r]))
		for _, s := range byReason[r] {
			fmt.Fprintf(w, "  %s\n", s)
		}
	}
}

// explainSpec answers for the specs whose text contains the substring.
func explainSpec(w *strings.Builder, audit Audit, substring string) {
	want := strings.ToLower(substring)
	var lines []string
	for _, s := range audit.Runs {
		if strings.Contains(strings.ToLower(s), want) {
			lines = append(lines, "runs     "+s)
		}
	}
	for _, d := range audit.Drops {
		if strings.Contains(strings.ToLower(d.Spec), want) {
			lines = append(lines, "dropped  "+d.Spec+"\n         "+d.Reason)
		}
	}
	if len(lines) == 0 {
		fmt.Fprintf(w, "No spec containing %q is selected by a suite of this lane, so none runs and none is dropped.\n", substring)
		return
	}

	sort.Strings(lines)
	for i, line := range lines {
		if i == maxExplained {
			fmt.Fprintf(w, "... and %d more, narrow the spec text\n", len(lines)-maxExplained)
			break
		}
		fmt.Fprintln(w, line)
	}
}
