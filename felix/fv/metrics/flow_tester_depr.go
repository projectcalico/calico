// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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

package metrics

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/flowlog"
)

// This flow tester makes too many assumptions about the tests, so isn't particularly useful for handling more
// complicated test cases (e.g. involving flows changing policy matches or action).  Let's deprecate this one
// in favor of the new FlowTester which will be easier to extend to test more flow data.

const (
	NoService = "- - - 0"
)

// FlowTesterDeprecated is a helper utility to parse and check flows.
type FlowTesterDeprecated struct {
	destPort       int
	destPortStr    string
	expectLabels   bool
	expectPolicies bool
	readers        []FlowLogReader
	flowsStarted   []map[flowlog.FlowMeta]int
	flowsCompleted []map[flowlog.FlowMeta]int
	packets        []map[flowlog.FlowMeta]int
	policies       []map[flowlog.FlowMeta][]string

	// Windows VXLAN can't complete a flow in time.
	IgnoreStartCompleteCount bool
}

// NewFlowTesterDeprecated creates a new FlowTesterDeprecated initialized for the supplied felix instances.
func NewFlowTesterDeprecated(readers []FlowLogReader, expectLabels, expectPolicies bool, destPort int) *FlowTesterDeprecated {
	return &FlowTesterDeprecated{
		destPort:       destPort,
		destPortStr:    fmt.Sprint(destPort),
		expectLabels:   expectLabels,
		expectPolicies: expectPolicies,
		readers:        readers,
		flowsStarted:   make([]map[flowlog.FlowMeta]int, len(readers)),
		flowsCompleted: make([]map[flowlog.FlowMeta]int, len(readers)),
		packets:        make([]map[flowlog.FlowMeta]int, len(readers)),
		policies:       make([]map[flowlog.FlowMeta][]string, len(readers)),
	}
}

// PopulateFromFlowLogs initializes the flow tester from the flow logs.
func (t *FlowTesterDeprecated) PopulateFromFlowLogs() error {
	for ii, f := range t.readers {
		t.flowsStarted[ii] = make(map[flowlog.FlowMeta]int)
		t.flowsCompleted[ii] = make(map[flowlog.FlowMeta]int)
		t.packets[ii] = make(map[flowlog.FlowMeta]int)
		t.policies[ii] = make(map[flowlog.FlowMeta][]string)

		cwlogs, err := f.FlowLogs()
		if err != nil {
			return err
		}

		for _, fl := range cwlogs {
			if fl.Tuple.GetDestPort() != t.destPort {
				continue
			}

			// If endpoint Labels are expected, and
			// aggregation permits this, check that they are
			// there.
			labelsExpected := t.expectLabels
			if labelsExpected {
				if fl.FlowLabels.SrcLabels == nil {
					return fmt.Errorf("missing src Labels in %v: Meta %v", fl.FlowLabels, fl.FlowMeta)
				}
				if fl.FlowLabels.DstLabels == nil {
					return fmt.Errorf("missing dst Labels in %v", fl.FlowLabels)
				}
			} else {
				if len(fl.FlowLabels.SrcLabels) != 0 {
					return fmt.Errorf("unexpected src Labels in %v", fl.FlowLabels)
				}
				if len(fl.FlowLabels.DstLabels) != 0 {
					return fmt.Errorf("unexpected dst Labels in %v", fl.FlowLabels)
				}
			}

			// Now discard Labels so that our expectation code
			// below doesn't ever have to specify them.
			fl.FlowLabels.SrcLabels = nil
			fl.FlowLabels.DstLabels = nil

			if t.expectPolicies {
				if len(fl.FlowPolicySet) == 0 {
					return fmt.Errorf("missing Policies in %v", fl.FlowMeta)
				}
				pols := []string{}
				for p := range fl.FlowPolicySet {
					pols = append(pols, p)
				}
				t.policies[ii][fl.FlowMeta] = pols
			} else if len(fl.FlowPolicySet) != 0 {
				return fmt.Errorf("unexpected Policies %v in %v", fl.FlowPolicySet, fl.FlowMeta)
			}

			// Accumulate flow and packet counts for this FlowMeta.
			t.flowsStarted[ii][fl.FlowMeta] += fl.NumFlowsStarted
			t.flowsCompleted[ii][fl.FlowMeta] += fl.NumFlowsCompleted
			t.packets[ii][fl.FlowMeta] += fl.PacketsIn + fl.PacketsOut
		}
		for meta, count := range t.flowsStarted[ii] {
			log.Infof("started: %d %v", count, meta)
		}
		for meta, count := range t.flowsCompleted[ii] {
			log.Infof("completed: %d %v", count, meta)
		}

		for meta, pols := range t.policies[ii] {
			log.Infof("Policies: %v %v", pols, meta)
		}

		if !t.IgnoreStartCompleteCount {
			// For each distinct FlowMeta, the counts of flows started
			// and completed should be the same.
			for meta, count := range t.flowsCompleted[ii] {
				if count != t.flowsStarted[ii][meta] {
					return fmt.Errorf("wrong started count (%d != %d) for %v",
						t.flowsStarted[ii][meta], count, meta)
				}
			}
		}

		// Check that we have non-zero packets for each flow.
		for meta, count := range t.packets[ii] {
			if count == 0 {
				return fmt.Errorf("no packets for %v", meta)
			}
		}
	}

	return nil
}

// CheckFlow flow logs with the given src/dst metadata and IPs.
// Specifically there should be numMatchingMetas distinct
// FlowMetas that match those, and numFlowsPerMeta flows for each
// distinct FlowMeta.  actions indicates the expected handling on
// each host: "allow" or "deny"; or "" if the flow isn't
// explicitly allowed or denied on that host (which means that
// there won't be a flow log).
func (t *FlowTesterDeprecated) CheckFlow(srcMeta, srcIP, dstMeta, dstIP, dstSvc string, numMatchingMetas, numFlowsPerMeta int, actionsPolicies []ExpectedPolicy) error {

	var errs []string

	// Validate input.
	Expect(actionsPolicies).To(HaveLen(len(t.readers)), "ActionsPolicies should be specified for each felix instance monitored by the FlowTesterDeprecated")

	// Host loop.
	for ii, handling := range actionsPolicies {
		// Skip if the handling for this host is "".
		if handling.Action == "" && handling.Reporter == "" {
			continue
		}
		reporter := handling.Reporter
		action := handling.Action
		expectedPolicies := []string{}
		expectedPoliciesStr := "-"
		if t.expectPolicies {
			expectedPolicies = handling.Policies
			expectedPoliciesStr = "[" + strings.Join(expectedPolicies, ",") + "]"
		}

		// Build a FlowMeta with the metadata and IPs that we are looking for.
		var template string
		if dstIP != "" {
			template = "1 2 " + srcMeta + " - " + dstMeta + " - " + srcIP + " " + dstIP + " 6 0 " + t.destPortStr + " 1 1 0 " + reporter + " 4 6 260 364 " + action + " " + expectedPoliciesStr + " - 0 " + dstSvc + " - 0 - 0 0 0 0 0 0 0 0 0 0 0 0"
		} else {
			template = "1 2 " + srcMeta + " - " + dstMeta + " - - - 6 0 " + t.destPortStr + " 1 1 0 " + reporter + " 4 6 260 364 " + action + " " + expectedPoliciesStr + " - 0 " + dstSvc + " - 0 - 0 0 0 0 0 0 0 0 0 0 0 0"
		}
		fl := &flowlog.FlowLog{}
		err := fl.Deserialize(template)
		Expect(err).ToNot(HaveOccurred())
		log.WithField("template", template).WithField("meta", fl.FlowMeta).Info("Looking for")
		if t.expectPolicies {
			for meta, actualPolicies := range t.policies[ii] {
				fl.FlowMeta.Tuple = fl.FlowMeta.Tuple.WithSourcePort(meta.Tuple.GetSourcePort())
				if meta != fl.FlowMeta {
					continue
				}

				// Sort the policies - they should be identical.
				sort.Strings(expectedPolicies)
				sort.Strings(actualPolicies)

				if !reflect.DeepEqual(expectedPolicies, actualPolicies) {
					errs = append(errs, fmt.Sprintf("Expected Policies %v to be present in %v", expectedPolicies, actualPolicies))
				}

				// Record that we've ticked off this flow.
				t.policies[ii][meta] = []string{}
			}
			fl.FlowMeta.Tuple = fl.FlowMeta.Tuple.WithSourcePort(0)
		}

		matchingMetas := 0
		for meta, count := range t.flowsCompleted[ii] {
			fl.FlowMeta.Tuple = fl.FlowMeta.Tuple.WithSourcePort(meta.Tuple.GetSourcePort())
			if meta == fl.FlowMeta {
				// This flow log matches what
				// we're looking for.
				if !t.IgnoreStartCompleteCount {
					if count != numFlowsPerMeta {
						errs = append(errs, fmt.Sprintf("Wrong flow count (%d != %d) for %v", count, numFlowsPerMeta, meta))
					}
				}
				matchingMetas += 1
				// Record that we've ticked off this flow.
				t.flowsCompleted[ii][meta] = 0
			}
		}
		fl.FlowMeta.Tuple = fl.FlowMeta.Tuple.WithSourcePort(0)
		if matchingMetas != numMatchingMetas {
			errs = append(errs, fmt.Sprintf("Wrong log count (%d != %d) for %v", matchingMetas, numMatchingMetas, fl.FlowMeta))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "\n==============\n"))
}

func (t *FlowTesterDeprecated) CheckAllFlowsAccountedFor() error {
	// Finally check that there are no remaining flow logs that we did not expect.
	var errs []string
	for ii := range t.readers {
		for meta, count := range t.flowsCompleted[ii] {
			if count != 0 {
				errs = append(errs, fmt.Sprintf("Unexpected flow logs (%d) for %v", count, meta))
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "\n==============\n"))
}

func (t *FlowTesterDeprecated) IterFlows(flowLogsOutput string, cb func(flowlog.FlowLog) error) error {
	for _, f := range t.readers {
		flogs, err := f.FlowLogs()
		if err != nil {
			return err
		}
		for _, fl := range flogs {
			if err := cb(fl); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *FlowTesterDeprecated) GetFlows(flowLogsOutput string) []flowlog.FlowLog {
	logs := []flowlog.FlowLog{}
	for _, f := range t.readers {
		flogs, err := f.FlowLogs()
		if err == nil {
			logs = append(logs, flogs...)
		}
	}
	return logs
}
