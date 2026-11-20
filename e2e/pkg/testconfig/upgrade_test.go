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
)

const upgradeLaneYAML = `
include:
  - Conformance && sig-calico
exclude:
  labels:
    - label: Upgrade:Seed
      reason: "upgrade phases only"
    - label: Upgrade:Verify
      reason: "upgrade phases only"
    - label: Dataplane:BPF
      reason: "iptables lane"
provides:
  - CalicoIPAM
`

func loadUpgradeLane(t *testing.T) *Config {
	t.Helper()
	cfg, err := LoadAll([]string{writeFile(t, t.TempDir(), "lane.yaml", upgradeLaneYAML)})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	return cfg
}

var (
	seedV333   = []string{"sig-calico", "Feature:IPAM", UpgradeSeedLabel, "UpgradeFrom:v3.32", "UpgradeFrom:v3.33"}
	verifyV333 = []string{"sig-calico", "Feature:IPAM", UpgradeVerifyLabel, "UpgradeFrom:v3.32", "UpgradeFrom:v3.33"}
	seedV332   = []string{"sig-calico", UpgradeSeedLabel, "UpgradeFrom:v3.32"}
	normalSpec = []string{"Conformance", "sig-calico"}
)

// Without a phase the scenario specs stay excluded, even from a lane whose
// scope would otherwise reach them through a Feature: label.
func TestUpgradePhaseUnsetLeavesScenariosOut(t *testing.T) {
	cfg := loadUpgradeLane(t)
	if err := ApplyUpgradePhase(cfg, "", ""); err != nil {
		t.Fatalf("ApplyUpgradePhase: %v", err)
	}
	checkSelection(t, cfg, []selectionCase{
		{labels: normalSpec, runs: true},
		{labels: append([]string{"Conformance"}, seedV333...), runs: false},
		{labels: append([]string{"Conformance"}, verifyV333...), runs: false},
	})
}

// Seed runs only the seed specs for this stream, still honouring the lane's
// platform excludes and provides.
func TestUpgradePhaseSeed(t *testing.T) {
	cfg := loadUpgradeLane(t)
	if err := ApplyUpgradePhase(cfg, UpgradePhaseSeed, "v3.33"); err != nil {
		t.Fatalf("ApplyUpgradePhase: %v", err)
	}
	checkSelection(t, cfg, []selectionCase{
		{labels: seedV333, runs: true},
		{labels: seedV332, runs: false},
		{labels: verifyV333, runs: false},
		{labels: normalSpec, runs: false},
		{labels: append(seedV333, "Dataplane:BPF"), runs: false},
		{labels: append(seedV333, "Requires:CalicoIPAM"), runs: true},
		{labels: append(seedV333, "Requires:BGP"), runs: false},
	})
}

// Verify adds this stream's verify specs to the lane's normal scope and never
// re-runs a seed spec on the upgraded cluster.
func TestUpgradePhaseVerify(t *testing.T) {
	cfg := loadUpgradeLane(t)
	if err := ApplyUpgradePhase(cfg, UpgradePhaseVerify, "v3.33"); err != nil {
		t.Fatalf("ApplyUpgradePhase: %v", err)
	}
	checkSelection(t, cfg, []selectionCase{
		{labels: normalSpec, runs: true},
		{labels: verifyV333, runs: true},
		{labels: []string{"sig-calico", UpgradeVerifyLabel, "UpgradeFrom:v3.32"}, runs: false},
		// The lane's own include must not reach another stream's verify spec.
		{labels: []string{"Conformance", "sig-calico", UpgradeVerifyLabel, "UpgradeFrom:v3.32"}, runs: false},
		{labels: seedV333, runs: false},
		{labels: append([]string{"Conformance"}, seedV333...), runs: false},
		{labels: append(verifyV333, "Dataplane:BPF"), runs: false},
	})
}

func TestUpgradePhaseRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ phase, from, want string }{
		{"seed", "", "release stream"},
		{"seed", "v3.33 || Slow", "release stream"},
		{"upgrade", "v3.33", "want"},
		{"", "v3.33", "without"},
	} {
		err := ApplyUpgradePhase(loadUpgradeLane(t), tc.phase, tc.from)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ApplyUpgradePhase(%q, %q) = %v, want error containing %q", tc.phase, tc.from, err, tc.want)
		}
	}
}

// An include-less lane keeps selecting everything else alongside its verify
// specs.
func TestUpgradePhaseVerifyOnIncludeLessLane(t *testing.T) {
	cfg, err := LoadAll([]string{writeFile(t, t.TempDir(), "lane.yaml", `exclude:
  labels:
    - label: Upgrade:Seed
      reason: "upgrade phases only"
    - label: Upgrade:Verify
      reason: "upgrade phases only"
`)})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := ApplyUpgradePhase(cfg, UpgradePhaseVerify, "v3.33"); err != nil {
		t.Fatalf("ApplyUpgradePhase: %v", err)
	}
	checkSelection(t, cfg, []selectionCase{
		{labels: normalSpec, runs: true},
		{labels: verifyV333, runs: true},
		{labels: []string{"sig-calico", UpgradeVerifyLabel, "UpgradeFrom:v3.32"}, runs: false},
		{labels: seedV333, runs: false},
	})
}

// A normal run of a lane that doesn't extend base.yaml still leaves the
// scenario specs out.
func TestUpgradePhaseUnsetWithoutBaseExcludes(t *testing.T) {
	cfg, err := LoadAll([]string{writeFile(t, t.TempDir(), "lane.yaml", "include:\n  - sig-calico\n")})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := ApplyUpgradePhase(cfg, "", ""); err != nil {
		t.Fatalf("ApplyUpgradePhase: %v", err)
	}
	checkSelection(t, cfg, []selectionCase{
		{labels: normalSpec, runs: true},
		{labels: seedV333, runs: false},
		{labels: verifyV333, runs: false},
	})
}

// A lane config that forgot base.yaml would otherwise run scenario specs in
// every normal run.
func TestUpgradePhaseNeedsBaseExcludes(t *testing.T) {
	cfg, err := LoadAll([]string{writeFile(t, t.TempDir(), "lane.yaml", "include:\n  - sig-calico\n")})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := ApplyUpgradePhase(cfg, UpgradePhaseVerify, "v3.33"); err == nil {
		t.Fatal("ApplyUpgradePhase accepted a lane that doesn't exclude the upgrade labels")
	}
}

// A phase include on a name-pattern lane would AND with its focus, so verify
// would drop the lane's whole normal suite.
func TestUpgradePhaseRejectsNamePatternLane(t *testing.T) {
	lane := namePatternsYAML + `exclude:
  labels:
    - label: Upgrade:Seed
      reason: "upgrade phases only"
    - label: Upgrade:Verify
      reason: "upgrade phases only"
`
	for _, phase := range []string{UpgradePhaseSeed, UpgradePhaseVerify} {
		cfg, err := LoadAll([]string{writeFile(t, t.TempDir(), "lane.yaml", lane)})
		if err != nil {
			t.Fatalf("LoadAll: %v", err)
		}
		if err := ApplyUpgradePhase(cfg, phase, "v3.33"); err == nil || !strings.Contains(err.Error(), "name pattern") {
			t.Errorf("ApplyUpgradePhase(%s) on a name-pattern lane = %v, want a name pattern error", phase, err)
		}
	}
}

// The seed run's real config list: a lane plus the scenarios.yaml marker.
func TestUpgradePhasesOnRepoLane(t *testing.T) {
	lane := []string{"../../config/upgrade/xtables.yaml", "../../config/upgrade/scenarios.yaml"}

	seed, err := LoadAll(lane)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := ApplyUpgradePhase(seed, UpgradePhaseSeed, "v3.33"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	checkSelection(t, seed, []selectionCase{
		{labels: seedV333, runs: true},
		{labels: []string{"Conformance", "sig-calico"}, runs: false},
		{labels: append(seedV333, "Dataplane:BPF"), runs: false},
	})

	verify, err := LoadAll(lane[:1])
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := ApplyUpgradePhase(verify, UpgradePhaseVerify, "v3.33"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	checkSelection(t, verify, []selectionCase{
		{labels: verifyV333, runs: true},
		{labels: []string{"Conformance", "sig-calico"}, runs: true},
		{labels: seedV333, runs: false},
	})
}
