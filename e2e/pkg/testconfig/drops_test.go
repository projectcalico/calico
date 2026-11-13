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

package testconfig

import (
	"regexp"
	"testing"

	"github.com/onsi/ginkgo/v2/types"
)

const legacyPatternYAML = `
exclude:
  namePatterns:
    - pattern: "DataPath"
      reason: "directory-based test name, not a Ginkgo label"
`

// dropCase is a spec and the reason the lane should give for dropping it, or
// "" when the lane should keep it.
type dropCase struct {
	name   string
	spec   Spec
	reason string
}

func loadDropper(t *testing.T, yamls ...string) (*Config, *Dropper) {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, y := range yamls {
		paths = append(paths, writeFile(t, dir, string(rune('a'+i))+".yaml", y))
	}
	cfg, err := LoadAll(paths)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	dropper, err := NewDropper(cfg)
	if err != nil {
		t.Fatalf("NewDropper: %v", err)
	}
	return cfg, dropper
}

// Every kind of drop reports the reason its category promises, and a spec the
// lane keeps reports none.
func TestDropperReasons(t *testing.T) {
	cfg, dropper := loadDropper(t, policySuiteYAML, calicoCNIYAML, eksYAML, legacyPatternYAML, quarantineYAML)

	cases := []dropCase{
		{name: "kept", spec: Spec{Text: "policy allows traffic", Labels: []string{"sig-calico", "Covers:NetworkPolicy", "Requires:CalicoCNI"}}},
		{name: "capability", spec: Spec{Text: "BGP peering", Labels: []string{"sig-calico", "Requires:BGP", "Requires:CalicoCNI"}}, reason: "Requires:BGP not provided"},
		{name: "several capabilities", spec: Spec{Text: "BGP in a VM", Labels: []string{"Requires:KubeVirt", "Requires:BGP"}}, reason: "Requires:BGP, Requires:KubeVirt not provided"},
		{name: "upstream", spec: Spec{Text: "DNS for services resolves", Labels: []string{"sig-network"}}, reason: "upstream: EKS control plane cannot reach the pod network"},
		{name: "label", spec: Spec{Text: "slow policy", Labels: []string{"Slow"}}, reason: "label Slow: too slow for CI"},
		{name: "name pattern", spec: Spec{Text: "DataPath checks", Labels: []string{"sig-calico"}}, reason: "excluded: directory-based test name, not a Ginkgo label"},
		{name: "quarantine", spec: Spec{Text: "should allow traffic to a host endpoint", Labels: []string{"sig-calico"}}, reason: "quarantine: CORE-13670"},
	}
	for _, c := range cases {
		got, dropped := dropper.Reason(c.spec)
		if dropped != (c.reason != "") || got != c.reason {
			t.Errorf("%s: Reason = %q, %v; want %q", c.name, got, dropped, c.reason)
		}
	}
	checkAgreesWithGinkgo(t, cfg, dropper, cases)
}

// A spec dropped by several rules is reported once, under the first of: a
// missing capability, an upstream gap, a label, a name pattern, a quarantine.
func TestDropperReportsFirstReason(t *testing.T) {
	_, dropper := loadDropper(t, policySuiteYAML, calicoCNIYAML, eksYAML, legacyPatternYAML, quarantineYAML)

	cases := []dropCase{
		{
			name:   "capability before quarantine",
			spec:   Spec{Text: "should allow traffic to a host endpoint", Labels: []string{"Requires:BGP"}},
			reason: "Requires:BGP not provided",
		},
		{
			name:   "upstream before label",
			spec:   Spec{Text: "DNS for services is Slow", Labels: []string{"Slow"}},
			reason: "upstream: EKS control plane cannot reach the pod network",
		},
		{
			name:   "label before quarantine",
			spec:   Spec{Text: "should allow traffic to a host endpoint", Labels: []string{"Slow"}},
			reason: "label Slow: too slow for CI",
		},
		{
			name:   "name pattern before quarantine",
			spec:   Spec{Text: "DataPath should allow traffic to a host endpoint"},
			reason: "excluded: directory-based test name, not a Ginkgo label",
		},
	}
	for _, c := range cases {
		if got, _ := dropper.Reason(c.spec); got != c.reason {
			t.Errorf("%s: Reason = %q, want %q", c.name, got, c.reason)
		}
	}
}

// Without a ticket a name pattern is a plain exclusion, even with a date, so
// only a ticketed entry counts as a quarantine.
func TestDropperRequiresTicketForQuarantine(t *testing.T) {
	_, dropper := loadDropper(t, `
exclude:
  namePatterns:
    - pattern: "broken spec"
      reason: "being rewritten"
      quarantined: 2026-09-18
`)
	got, dropped := dropper.Reason(Spec{Text: "a broken spec"})
	if !dropped || got != "excluded: being rewritten" {
		t.Errorf("Reason = %q, %v; want the plain exclusion", got, dropped)
	}
}

// A lane that never declared provides keeps specs whatever they require.
func TestDropperWithoutProvidesIgnoresRequires(t *testing.T) {
	_, dropper := loadDropper(t, policySuiteYAML)
	if got, dropped := dropper.Reason(Spec{Text: "x", Labels: []string{"Requires:BGP"}}); dropped {
		t.Errorf("Reason = %q, want the spec kept", got)
	}
}

func TestTicketKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://tigera.atlassian.net/browse/CORE-13670":  "CORE-13670",
		"https://tigera.atlassian.net/browse/CORE-13670/": "CORE-13670",
		"CORE-13670": "CORE-13670",
	} {
		if got := ticketKey(in); got != want {
			t.Errorf("ticketKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// IncludeOnly keeps what the suites select and nothing that drops specs.
func TestIncludeOnlyDropsNoSpec(t *testing.T) {
	cfg, _ := loadDropper(t, policySuiteYAML, calicoCNIYAML, eksYAML, quarantineYAML)
	dropper, err := NewDropper(cfg.IncludeOnly())
	if err != nil {
		t.Fatalf("NewDropper: %v", err)
	}
	for _, s := range []Spec{
		{Text: "DNS for services", Labels: []string{"Slow"}},
		{Text: "should allow traffic to a host endpoint", Labels: []string{"Requires:BGP"}},
	} {
		if got, dropped := dropper.Reason(s); dropped {
			t.Errorf("include-only config drops %q: %s", s.Text, got)
		}
	}
	if len(cfg.IncludeOnly().Include.Labels) == 0 {
		t.Errorf("IncludeOnly lost the include labels")
	}
}

// checkAgreesWithGinkgo confirms the Dropper drops exactly the specs the
// config's own label filter and skip regex would, so a reason is never given for
// a spec the binary runs, nor withheld from one it skips.
func checkAgreesWithGinkgo(t *testing.T, cfg *Config, dropper *Dropper, cases []dropCase) {
	t.Helper()
	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}
	filter, err := types.ParseLabelFilter(flags.LabelFilter)
	if err != nil {
		t.Fatalf("ParseLabelFilter: %v", err)
	}
	skip := regexp.MustCompile(flags.SkipString())
	for _, c := range cases {
		inFilter := filter(c.spec.Labels)
		skipped := skip.MatchString(c.spec.Suite + " " + c.spec.Text)
		_, dropped := dropper.Reason(c.spec)
		if want := skipped || !inFilter; dropped != want {
			t.Errorf("%s: Dropper drops = %v, ginkgo drops = %v", c.name, dropped, want)
		}
	}
}
