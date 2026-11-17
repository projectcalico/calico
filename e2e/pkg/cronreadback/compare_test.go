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
	"testing"

	. "github.com/onsi/gomega"
)

func expectedBPF() ExpectedCron {
	return ExpectedCron{
		Name: "e2e-bpf-master",
		File: ".argoci/cron/e2e-bpf.yaml",
		Cells: map[string]string{
			"wireguard":    "e2e/config/bpf/bpf.yaml",
			"multi-config": "e2e/config/ci-base.yaml e2e/config/suite/policy.yaml",
		},
	}
}

func liveBPF() LiveCron {
	return LiveCron{
		Name: "e2e-bpf-master",
		Cells: map[string]string{
			"wireguard":    "e2e/config/bpf/bpf.yaml",
			"multi-config": "e2e/config/ci-base.yaml\n  e2e/config/suite/policy.yaml",
		},
	}
}

func liveSetOf(crons ...LiveCron) LiveSet {
	set := LiveSet{Crons: map[string]LiveCron{}}
	for _, c := range crons {
		set.Crons[c.Name] = c
		set.Names = append(set.Names, c.Name)
	}
	return set
}

func TestCompareMatching(t *testing.T) {
	RegisterTestingT(t)

	// A folded config list is the same list.
	Expect(Compare([]ExpectedCron{expectedBPF()}, liveSetOf(liveBPF()))).To(BeEmpty())
}

func TestCompareConfigMismatch(t *testing.T) {
	RegisterTestingT(t)

	live := liveBPF()
	live.Cells["wireguard"] = "e2e/config/old/wireguard.yaml"

	Expect(Compare([]ExpectedCron{expectedBPF()}, liveSetOf(live))).To(Equal([]Finding{{
		Kind: ConfigMismatch,
		Cron: "e2e-bpf-master",
		Cell: "wireguard",
		Want: "e2e/config/bpf/bpf.yaml",
		Got:  "e2e/config/old/wireguard.yaml",
	}}))
}

func TestCompareConfigOrderMatters(t *testing.T) {
	RegisterTestingT(t)

	live := liveBPF()
	live.Cells["multi-config"] = "e2e/config/suite/policy.yaml e2e/config/ci-base.yaml"

	findings := Compare([]ExpectedCron{expectedBPF()}, liveSetOf(live))
	Expect(findings).To(HaveLen(1))
	Expect(findings[0].Kind).To(Equal(ConfigMismatch))
}

func TestCompareMissingCron(t *testing.T) {
	RegisterTestingT(t)

	Expect(Compare([]ExpectedCron{expectedBPF()}, liveSetOf())).To(Equal([]Finding{
		{Kind: MissingCron, Cron: "e2e-bpf-master"},
	}))
}

func TestCompareExtraCron(t *testing.T) {
	RegisterTestingT(t)

	stale := LiveCron{Name: "e2e-retired-master"}

	Expect(Compare([]ExpectedCron{expectedBPF()}, liveSetOf(liveBPF(), stale))).To(Equal([]Finding{
		{Kind: ExtraCron, Cron: "e2e-retired-master"},
	}))
}

func TestCompareMissingCell(t *testing.T) {
	RegisterTestingT(t)

	live := liveBPF()
	delete(live.Cells, "wireguard")

	Expect(Compare([]ExpectedCron{expectedBPF()}, liveSetOf(live))).To(Equal([]Finding{{
		Kind: MissingCell,
		Cron: "e2e-bpf-master",
		Cell: "wireguard",
		Want: "e2e/config/bpf/bpf.yaml",
	}}))
}

func TestCompareExtraCell(t *testing.T) {
	RegisterTestingT(t)

	live := liveBPF()
	live.Cells["removed-from-file"] = "e2e/config/bpf/gone.yaml"

	Expect(Compare([]ExpectedCron{expectedBPF()}, liveSetOf(live))).To(Equal([]Finding{{
		Kind: ExtraCell,
		Cron: "e2e-bpf-master",
		Cell: "removed-from-file",
		Got:  "e2e/config/bpf/gone.yaml",
	}}))
}

func TestFindingString(t *testing.T) {
	RegisterTestingT(t)

	f := Finding{Kind: ConfigMismatch, Cron: "c", Cell: "x", Want: "a.yaml", Got: "b.yaml"}

	Expect(f.String()).To(Equal(`config mismatch: c / x want "a.yaml", live "b.yaml"`))
}

func TestCellCount(t *testing.T) {
	RegisterTestingT(t)

	Expect(CellCount([]ExpectedCron{expectedBPF(), {Name: "empty"}})).To(Equal(2))
}
