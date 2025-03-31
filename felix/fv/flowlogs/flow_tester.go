// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowlogs

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/flowlog"
)

const (
	// Source port values to use in the comparison. Use SourcePortIsIncluded if you expect the flow to include the
	// source port. Otherwise, use SourcePortIsNotIncluded.
	SourcePortIsIncluded    = -1
	SourcePortIsNotIncluded = 0
)

type FlowLogReader interface {
	FlowLogs() ([]flowlog.FlowLog, error)
}

// The expected policies for the flow.
type ExpectedPolicy struct {
	Reporter string
	Action   string
	Policies []string
}

// FlowTester is a helper utility to parse and check flows.
type FlowTester struct {
	options FlowTesterOptions
	flows   map[flowMeta]flowlog.FlowLog
	errors  []string
}

type FlowTesterOptions struct {
	// Whether to expect labels or policies in the flow logs
	ExpectLabels           bool
	ExpectEnforcedPolicies bool
	ExpectPendingPolicies  bool

	// Whether to include labels or policies in the match criteria
	MatchLabels           bool
	MatchEnforcedPolicies bool
	MatchPendingPolicies  bool

	// Set of include filters used to only include certain flows. Set of filters is ORed.
	Includes []IncludeFilter

	// What values to check.
	CheckPackets         bool // Checks packets in/out
	CheckBytes           bool // Checks bytes in/out
	CheckNumFlowsStarted bool // Checks expected number of flows were started
	CheckFlowsCompleted  bool // Checks the flows completed match the flows started
}

type flowMeta struct {
	flowlog.FlowMeta
	enforced string
	pending  string
	labels   string
}

type IncludeFilter func(flowlog.FlowLog) bool

func IncludeByDestPort(port int) IncludeFilter {
	return func(f flowlog.FlowLog) bool {
		return f.FlowMeta.Tuple.GetDestPort() == port
	}
}

// NewFlowTester creates a new FlowTesterDeprecated initialized for the supplied felix instances.
func NewFlowTester(options FlowTesterOptions) *FlowTester {
	return &FlowTester{
		options: options,
	}
}

// PopulateFromFlowLogs populates the flow tester from the flow logs. The flow tester may be re-used.
func (t *FlowTester) PopulateFromFlowLogs(reader FlowLogReader) error {
	// Reset the tester.
	t.reset()

	// Read flows from the logs.
	cwlogs, err := reader.FlowLogs()
	if err != nil {
		return err
	}

	// Populate the flows.
	for _, fl := range cwlogs {
		include := false
		for ii := range t.options.Includes {
			if t.options.Includes[ii](fl) {
				include = true
				break
			}
		}
		if !include {
			continue
		}

		// Check if labels or policies are expected.
		labelsExpected := t.options.ExpectLabels
		if labelsExpected {
			if fl.FlowLabels.SrcLabels == nil {
				return fmt.Errorf("missing src Labels in %v: Meta %v", fl.FlowLabels, fl.FlowMeta)
			}
			if fl.FlowLabels.DstLabels == nil {
				return fmt.Errorf("missing dst Labels in %v", fl.FlowLabels)
			}
		} else {
			if fl.FlowLabels.SrcLabels != nil {
				return fmt.Errorf("unexpected src Labels in %v", fl.FlowLabels)
			}
			if fl.FlowLabels.DstLabels != nil {
				return fmt.Errorf("unexpected dst Labels in %v", fl.FlowLabels)
			}
		}
		if t.options.ExpectEnforcedPolicies {
			if len(fl.FlowEnforcedPolicySet) == 0 {
				return fmt.Errorf("missing enforced policies in %v", fl.FlowMeta)
			}
		} else if len(fl.FlowEnforcedPolicySet) != 0 {
			return fmt.Errorf("unexpected enforced policies %v in %v", fl.FlowEnforcedPolicySet, fl.FlowMeta)
		}
		if t.options.ExpectPendingPolicies {
			if len(fl.FlowPendingPolicySet) == 0 {
				return fmt.Errorf("missing pending policies in %v", fl.FlowMeta)
			}
		}

		// Never include source port as it is usually ephemeral and difficult to test for.  Instead if the source port
		// is 0 then leave as 0 (since it is aggregated out), otherwise set to -1.
		if fl.FlowMeta.Tuple.GetSourcePort() != SourcePortIsNotIncluded {
			fl.FlowMeta.Tuple = fl.FlowMeta.Tuple.WithSourcePort(SourcePortIsIncluded)
		}

		fm := t.flowMetaFromFlowLog(fl)
		existing, ok := t.flows[fm]
		if !ok {
			t.flows[fm] = fl
			continue
		}

		// Update the flow.
		if fl.StartTime.Before(existing.StartTime) {
			fl.EndTime = existing.EndTime
		} else {
			fl.StartTime = existing.StartTime
		}
		existing.EndTime = fl.EndTime
		fl.FlowReportedStats.Add(existing.FlowReportedStats)
		t.flows[fm] = fl
	}

	if t.options.CheckFlowsCompleted {
		// For each distinct FlowMeta, the counts of flows started and completed should be the same.
		for fm, fl := range t.flows {
			if fl.FlowReportedStats.NumFlowsStarted != fl.FlowReportedStats.NumFlowsCompleted {
				return fmt.Errorf("flow started/completed counts do not match (%d != %d): %#v",
					fl.FlowReportedStats.NumFlowsStarted, fl.FlowReportedStats.NumFlowsCompleted, fm)
			}
		}
	}

	// Check that we have non-zero packets for each flow.
	for fm, fl := range t.flows {
		if fl.FlowReportedStats.PacketsOut+fl.FlowReportedStats.PacketsIn == 0 {
			return fmt.Errorf("flow has no packets: %#v", fm)
		}
	}

	return nil
}

// CheckFlow checks that the flow specified is in the logs.  Flows are identified by:
// - FlowMeta
// - (optionally) Policies
// - (optionally) Labels
//
// And checks:
// - FlowLogStatistics
//
// After CheckFlow has been called for all expected flows, call Finish to check that everything has
// been explicitly checked.
func (t *FlowTester) CheckFlow(fl flowlog.FlowLog) {
	fm := t.flowMetaFromFlowLog(fl)
	for key, flow := range t.flows {
		log.Infof("key: %v", key)
		log.Infof("flow: %v", flow)
	}
	existing, ok := t.flows[fm]
	if !ok {
		t.errors = append(t.errors, fmt.Sprintf("Flow was not present in logs: %#v", fm))
		return
	}
	delete(t.flows, fm)

	var errs []string
	if t.options.CheckBytes {
		if fl.BytesIn != existing.BytesIn {
			errs = append(errs, fmt.Sprintf("BytesIn actual != expected (%d != %d)", existing.BytesIn, fl.BytesIn))
		}
		if fl.BytesOut != existing.BytesOut {
			errs = append(errs, fmt.Sprintf("BytesOut actual != expected (%d != %d)", existing.BytesOut, fl.BytesOut))
		}
	}

	if t.options.CheckPackets {
		if fl.PacketsIn != existing.PacketsIn {
			errs = append(errs, fmt.Sprintf("PacketsIn actual != expected (%d != %d)", existing.PacketsIn, fl.PacketsIn))
		}
		if fl.PacketsOut != existing.PacketsOut {
			errs = append(errs, fmt.Sprintf("PacketsOut actual != expected (%d != %d)", existing.PacketsOut, fl.PacketsOut))
		}
	}

	if t.options.CheckNumFlowsStarted {
		if fl.NumFlowsStarted != existing.NumFlowsStarted {
			errs = append(errs, fmt.Sprintf("NumFlowsStarted actual != expected (%d != %d)", existing.NumFlowsStarted, fl.NumFlowsStarted))
		}
	}

	if len(errs) != 0 {
		t.errors = append(t.errors, fmt.Sprintf("Statistics incorrect: %#v\n- %s", fl, strings.Join(errs, "/n- ")))
	}
}

// Finish is called after CheckFlow is called for every expected flow. This returns an error containing all found
// deltas.
func (t *FlowTester) Finish() error {
	for _, fl := range t.flows {
		t.errors = append(t.errors, fmt.Sprintf("Unchecked flow: %#v", fl))
	}

	if len(t.errors) == 0 {
		return nil
	}
	return errors.New(strings.Join(t.errors, "\n==============\n"))
}

// Return a test-specific flowMeta from the flowLog.  We may include policies and labels in the metadata so that
// flows with different labels or policies will be expicitly matched.
func (t *FlowTester) flowMetaFromFlowLog(fl flowlog.FlowLog) flowMeta {
	// If we are including the labels or policies in the match then include them in the meta. We need to convert the
	// policies and labels to a single string to make it hashable.
	fm := flowMeta{
		FlowMeta: fl.FlowMeta,
	}
	if t.options.MatchLabels {
		var srcLabels, dstLabels []string
		for k, v := range fl.FlowLabels.SrcLabels {
			srcLabels = append(srcLabels, k+"="+v)
		}
		for k, v := range fl.FlowLabels.DstLabels {
			dstLabels = append(dstLabels, k+"="+v)
		}
		sort.Strings(srcLabels)
		sort.Strings(dstLabels)
		fm.labels = strings.Join(srcLabels, ";") + "|" + strings.Join(dstLabels, ";")
	}
	if t.options.MatchEnforcedPolicies {
		var enforced []string
		for p := range fl.FlowEnforcedPolicySet {
			enforced = append(enforced, p)
		}
		sort.Strings(enforced)
		fm.enforced += strings.Join(enforced, ";")
	}
	if t.options.MatchPendingPolicies {
		var pending []string
		for p := range fl.FlowPendingPolicySet {
			pending = append(pending, p)
		}
		sort.Strings(pending)
		fm.pending += strings.Join(pending, ";")
	}
	return fm
}

// Reset accumulated test data.
func (t *FlowTester) reset() {
	t.flows = make(map[flowMeta]flowlog.FlowLog)
	t.errors = nil
}
