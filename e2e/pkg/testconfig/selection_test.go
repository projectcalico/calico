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
	"strings"
	"testing"

	"github.com/onsi/ginkgo/v2/types"
)

const (
	policySuiteYAML = `
include:
  - sig-calico && (Covers:NetworkPolicy || Covers:TieredRBAC)
  - Conformance && sig-network
exclude:
  labels:
    - label: Slow
      reason: "too slow for CI"
`

	calicoCNIYAML = `
provides:
  - CalicoCNI
  - CalicoIPAM
`

	bgpYAML = `
needs:
  - cni/calico.yaml
provides:
  - BGP
`

	noCapabilitiesYAML = `
provides: []
`

	eksYAML = `
provides:
  - AWS
upstream:
  - group: "EKS control plane cannot reach the pod network"
    patterns:
      - 'DNS.for.services'
`

	quarantineYAML = `
exclude:
  namePatterns:
    - group: "Pods never reach Running on the host-endpoint lane"
      ticket: https://tigera.atlassian.net/browse/CORE-13670
      quarantined: 2026-09-18
      patterns:
        - 'should.allow.traffic.to.a.host.endpoint'
`

	badCapabilityYAML = `
provides:
  - Calico-CNI
`

	badDateYAML = `
exclude:
  namePatterns:
    - pattern: "x"
      reason: "broken"
      quarantined: 18/09/2026
`

	emptyNeedsYAML = `
needs:
  - ""
`

	badUpstreamYAML = `
upstream:
  - pattern: "("
    reason: "bad regex"
`
)

// selectionCase is a spec's labels and whether the lane should run it.
type selectionCase struct {
	labels []string
	runs   bool
}

// A spec runs only when the lane provides every capability it requires,
// whichever fragment provides each one.
func TestProvidesSelectsBySubset(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadAll([]string{
		writeFile(t, dir, "policy.yaml", policySuiteYAML),
		writeFile(t, dir, "calico.yaml", calicoCNIYAML),
		writeFile(t, dir, "bgp.yaml", bgpYAML),
	})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	checkSelection(t, cfg, []selectionCase{
		{labels: []string{"sig-calico", "Covers:NetworkPolicy"}, runs: true},
		{labels: []string{"sig-calico", "Covers:NetworkPolicy", "Requires:BGP"}, runs: true},
		{labels: []string{"sig-calico", "Covers:TieredRBAC", "Requires:BGP", "Requires:CalicoIPAM"}, runs: true},
		{labels: []string{"Conformance", "sig-network"}, runs: true},
		{labels: []string{"sig-calico", "Covers:NetworkPolicy", "Requires:Operator"}, runs: false},
		{labels: []string{"sig-calico", "Covers:NetworkPolicy", "Requires:BGP", "Requires:Operator"}, runs: false},
		{labels: []string{"sig-calico", "Covers:NetworkPolicy", "Slow"}, runs: false},
		{labels: []string{"sig-calico", "Covers:Wireguard"}, runs: false},
	})
}

// Without provides anywhere, Requires: labels play no part in selection, so a
// lane that hasn't moved to fragments selects exactly as before.
func TestNoProvidesIgnoresRequires(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadAll([]string{writeFile(t, dir, "policy.yaml", policySuiteYAML)})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if cfg.Provides != nil {
		t.Fatalf("Provides = %v, want nil when no config declares it", cfg.Provides)
	}

	checkSelection(t, cfg, []selectionCase{
		{labels: []string{"sig-calico", "Covers:NetworkPolicy", "Requires:Operator"}, runs: true},
	})
}

// An empty provides is a lane with no capabilities, not one that never said.
func TestEmptyProvidesDropsEverySpecWithRequirements(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadAll([]string{
		writeFile(t, dir, "policy.yaml", policySuiteYAML),
		writeFile(t, dir, "none.yaml", noCapabilitiesYAML),
	})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	checkSelection(t, cfg, []selectionCase{
		{labels: []string{"sig-calico", "Covers:NetworkPolicy"}, runs: true},
		{labels: []string{"sig-calico", "Covers:NetworkPolicy", "Requires:BGP"}, runs: false},
	})
}

// Upstream gaps are skipped by name, alongside the exclude name patterns, and
// needs is carried through the merge for the lane checks.
func TestUpstreamAndNeedsMerge(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadAll([]string{
		writeFile(t, dir, "eks.yaml", eksYAML),
		writeFile(t, dir, "bgp.yaml", bgpYAML),
		writeFile(t, dir, "quarantine.yaml", quarantineYAML),
	})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}
	skip := flags.SkipString()
	for _, want := range []string{"DNS.for.services", "should.allow.traffic.to.a.host.endpoint"} {
		if !strings.Contains(skip, want) {
			t.Errorf("skip %q is missing %q", skip, want)
		}
	}
	if len(cfg.Needs) != 1 || cfg.Needs[0] != "cni/calico.yaml" {
		t.Errorf("Needs = %v, want [cni/calico.yaml]", cfg.Needs)
	}
	if got := cfg.Exclude.NamePatterns[0]; got.Ticket == "" || got.Quarantined != "2026-09-18" {
		t.Errorf("quarantine entry ticket=%q quarantined=%q, want both set", got.Ticket, got.Quarantined)
	}
}

func TestSelectionFieldsRejectBadValues(t *testing.T) {
	dir := t.TempDir()
	for name, bad := range map[string]badValueCase{
		"capability.yaml": {content: badCapabilityYAML, wantErr: "must be a capability name"},
		"date.yaml":       {content: badDateYAML, wantErr: "is not YYYY-MM-DD"},
		"upstream.yaml":   {content: badUpstreamYAML, wantErr: "upstream[0]: invalid regex"},
		"needs.yaml":      {content: emptyNeedsYAML, wantErr: "needs[0] is empty"},
	} {
		_, err := Load(writeFile(t, dir, name, bad.content))
		if err == nil || !strings.Contains(err.Error(), bad.wantErr) {
			t.Errorf("Load(%s) err = %v, want one containing %q", name, err, bad.wantErr)
		}
	}
}

// badValueCase is a config holding one bad value and the error it must cause,
// so a file failing for some other reason doesn't pass the test.
type badValueCase struct {
	content string
	wantErr string
}

// checkSelection parses the config's label filter with Ginkgo's own parser
// and checks which label sets it keeps.
func checkSelection(t *testing.T, cfg *Config, cases []selectionCase) {
	t.Helper()
	flags, err := ToFlags(cfg)
	if err != nil {
		t.Fatalf("ToFlags: %v", err)
	}
	filter, err := types.ParseLabelFilter(flags.LabelFilter)
	if err != nil {
		t.Fatalf("Ginkgo rejected label filter %q: %v", flags.LabelFilter, err)
	}
	for _, c := range cases {
		if got := filter(c.labels); got != c.runs {
			t.Errorf("filter %q on %v = %v, want %v", flags.LabelFilter, c.labels, got, c.runs)
		}
	}
}
