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
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/e2e/pkg/testconfig"
)

const (
	laneSuiteYAML = `
include:
  - sig-calico
exclude:
  labels:
    - label: Slow
      reason: "too slow for CI"
`

	laneClusterYAML = `
provides:
  - CalicoCNI
`

	laneQuarantineYAML = `
exclude:
  namePatterns:
    - group: "Pods never reach Running on the host-endpoint lane"
      ticket: https://tigera.atlassian.net/browse/CORE-13670
      quarantined: 2026-09-18
      patterns:
        - 'host endpoint'
`

	laneUnticketedYAML = `
exclude:
  namePatterns:
    - pattern: 'host endpoint'
      reason: "being rewritten"
`
)

// laneSpecs are the specs the suite above selects, with the labels the binary
// would report for them.
var laneSpecs = []testconfig.Spec{
	{Text: "[sig-calico] BGP peering", Labels: []string{"sig-calico", "Requires:BGP"}},
	{Text: "[sig-calico] host endpoint allows traffic", Labels: []string{"sig-calico", "Requires:CalicoCNI"}},
	{Text: "[sig-calico] pod to pod", Labels: []string{"sig-calico", "Requires:CalicoCNI"}},
	{Text: "[sig-calico] slow upgrade", Labels: []string{"sig-calico", "Slow"}},
}

// auditFixture audits laneSpecs for a lane built from the given config files.
// The runs are what the binary would report, so the audit has to explain the
// rest.
func auditFixture(t *testing.T, runs []string, yamls ...string) (Audit, error) {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, y := range yamls {
		p := filepath.Join(dir, string(rune('a'+i))+".yaml")
		if err := os.WriteFile(p, []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	cfg, err := testconfig.LoadAll(paths)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	dropper, err := testconfig.NewDropper(cfg)
	if err != nil {
		t.Fatalf("NewDropper: %v", err)
	}

	var ran []testconfig.Spec
	for _, r := range runs {
		ran = append(ran, testconfig.Spec{Text: r})
	}
	return AuditSelection(laneSpecs, ran, dropper)
}

func TestAuditSelectionAttributesEveryDrop(t *testing.T) {
	RegisterTestingT(t)

	audit, err := auditFixture(t, []string{"[sig-calico] pod to pod"}, laneSuiteYAML, laneClusterYAML, laneQuarantineYAML)
	Expect(err).NotTo(HaveOccurred())

	Expect(audit.Runs).To(Equal([]string{"[sig-calico] pod to pod"}))
	Expect(audit.Drops).To(Equal([]Drop{
		{Spec: "[sig-calico] BGP peering", Reason: "Requires:BGP not provided"},
		{Spec: "[sig-calico] host endpoint allows traffic", Reason: "quarantine: CORE-13670"},
		{Spec: "[sig-calico] slow upgrade", Reason: "label Slow: too slow for CI"},
	}))
	Expect(audit.QuarantineCount()).To(Equal(1))
}

// The same pattern without a ticket is a plain exclusion, not a quarantine.
func TestQuarantineCountNeedsATicket(t *testing.T) {
	RegisterTestingT(t)

	excluded, err := auditFixture(t, []string{"[sig-calico] pod to pod"}, laneSuiteYAML, laneClusterYAML, laneUnticketedYAML)
	Expect(err).NotTo(HaveOccurred())
	Expect(excluded.QuarantineCount()).To(Equal(0))
}

// The binary decides what runs. A spec it skips that no rule explains means
// the dropper has diverged from the binary, and must fail rather than guess.
func TestAuditSelectionFailsWhenTheDropperDiverges(t *testing.T) {
	RegisterTestingT(t)

	_, err := auditFixture(t, []string{"[sig-calico] pod to pod"}, laneSuiteYAML)
	Expect(err).To(MatchError(ContainSubstring(`the binary skips "[sig-calico] BGP peering"`)))

	_, err = auditFixture(t, []string{"[sig-calico] pod to pod", "[sig-network] other"}, laneSuiteYAML, laneClusterYAML, laneQuarantineYAML)
	Expect(err).To(MatchError(ContainSubstring(`the binary runs "[sig-network] other"`)))
}

func TestFormatDrops(t *testing.T) {
	RegisterTestingT(t)

	drops := []Drop{
		{Spec: "[sig-calico] BGP peering", Reason: "Requires:BGP not provided"},
		{Spec: "[sig-calico] host endpoint", Reason: "quarantine: CORE-13670"},
	}
	Expect(FormatDrops(drops)).To(Equal("[sig-calico] BGP peering\tRequires:BGP not provided\n[sig-calico] host endpoint\tquarantine: CORE-13670\n"))
	Expect(drops[1].Quarantined()).To(BeTrue())
	Expect(drops[0].Quarantined()).To(BeFalse())
	Expect(FormatDrops(nil)).To(BeEmpty())
}

// A drop list is a committed file, so a changed reason has to change its text.
func TestFormatDropsShowsAChangedReason(t *testing.T) {
	RegisterTestingT(t)

	was := []Drop{{Spec: "spec", Reason: "quarantine: CORE-1"}}
	now := []Drop{{Spec: "spec", Reason: "Requires:BGP not provided"}}
	Expect(FormatDrops(was)).NotTo(Equal(FormatDrops(now)))
}

// Explain on a lane with a quarantine entry names the ticket, for the whole
// lane and for one spec.
func TestExplainNamesTheQuarantineTicket(t *testing.T) {
	RegisterTestingT(t)

	lane := Lane{Source: ".argoci/cron/e2e-iptables.yaml", Name: "host-endpoint [kind]", Config: "e2e/config/a.yaml e2e/config/b.yaml"}
	audit, err := auditFixture(t, []string{"[sig-calico] pod to pod"}, laneSuiteYAML, laneClusterYAML, laneQuarantineYAML)
	Expect(err).NotTo(HaveOccurred())

	all := Explain("cron/e2e-iptables/host-endpoint-kind", lane, audit, "")
	Expect(all).To(ContainSubstring("runs 1 specs, drops 3, 1 of them quarantined"))
	Expect(all).To(ContainSubstring("quarantine: CORE-13670 (1)\n  [sig-calico] host endpoint allows traffic"))

	one := Explain("cron/e2e-iptables/host-endpoint-kind", lane, audit, "HOST ENDPOINT")
	Expect(one).To(ContainSubstring("dropped  [sig-calico] host endpoint allows traffic\n         quarantine: CORE-13670"))
	Expect(one).NotTo(ContainSubstring("pod to pod"))

	running := Explain("cron/e2e-iptables/host-endpoint-kind", lane, audit, "pod to pod")
	Expect(running).To(ContainSubstring("runs     [sig-calico] pod to pod"))
	Expect(running).NotTo(ContainSubstring("CORE-13670"))

	absent := Explain("cron/e2e-iptables/host-endpoint-kind", lane, audit, "nothing like this")
	Expect(absent).To(ContainSubstring("is selected by a suite of this lane"))
}

// Without a ticket the same pattern is a plain exclusion, and explain does not
// call it a quarantine.
func TestExplainDoesNotQuarantineWithoutATicket(t *testing.T) {
	RegisterTestingT(t)

	audit, err := auditFixture(t, []string{"[sig-calico] pod to pod"}, laneSuiteYAML, laneClusterYAML, laneUnticketedYAML)
	Expect(err).NotTo(HaveOccurred())

	out := Explain("set", Lane{}, audit, "host endpoint")
	Expect(out).To(ContainSubstring("excluded: being rewritten"))
	Expect(out).NotTo(ContainSubstring("quarantine: "))
}

func TestFindLane(t *testing.T) {
	RegisterTestingT(t)

	a := Lane{Source: ".argoci/cron/a.yaml", Name: "one [x]", Area: "bpf.yml", Config: "e2e/config/bpf/bpf.yaml", TestType: "k8s-e2e"}
	b := Lane{Source: ".argoci/cron/b.yaml", Name: "one [x]", Area: "bpf.yml", Config: "e2e/config/bpf/bpf.yaml", TestType: "k8s-e2e"}
	c := Lane{Source: ".argoci/cron/b.yaml", Name: "two", Area: "bpf.yml", Config: "e2e/config/bpf/bpf.yaml", TestType: "k8s-e2e"}
	lanes := []Lane{a, b, c}

	name, lane, err := FindLane(lanes, "cron/a/one-x")
	Expect(err).NotTo(HaveOccurred())
	Expect(name).To(Equal("cron/a/one-x"))
	Expect(lane).To(Equal(a))

	name, _, err = FindLane(lanes, "two")
	Expect(err).NotTo(HaveOccurred())
	Expect(name).To(Equal("cron/b/two"))

	_, _, err = FindLane(lanes, "one [x]")
	Expect(err).To(MatchError(ContainSubstring("is in 2 sets")))

	_, _, err = FindLane(lanes, "three")
	Expect(err).To(MatchError(ContainSubstring("no lane has")))
}

func TestWriteRecordsDropsBesideSets(t *testing.T) {
	RegisterTestingT(t)

	lane := Lane{Source: ".argoci/cron/a.yaml", Name: "one", Area: "bpf.yml", Config: "e2e/config/bpf/bpf.yaml", TestType: "k8s-e2e"}
	audits := map[string]Audit{"cron/a/one": {
		Runs:  []string{"spec one"},
		Drops: []Drop{{Spec: "spec two", Reason: "quarantine: CORE-1"}},
	}}
	dir := t.TempDir()
	Expect(Write(dir, []Lane{lane}, audits)).To(Succeed())

	runs, err := os.ReadFile(filepath.Join(dir, "sets/cron/a/one.txt"))
	Expect(err).NotTo(HaveOccurred())
	Expect(string(runs)).To(Equal("spec one\n"))

	drops, err := os.ReadFile(filepath.Join(dir, "sets/cron/a/one.drops.txt"))
	Expect(err).NotTo(HaveOccurred())
	Expect(string(drops)).To(Equal("spec two\tquarantine: CORE-1\n"))
}
