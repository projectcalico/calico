// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggregator

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func setupTest(t *testing.T) func() {
	// Register gomega with test.
	RegisterTestingT(t)

	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)
	return func() {
		logCancel()
	}
}

func TestIndexAddRemove(t *testing.T) {
	defer setupTest(t)()

	// Create an index, ordered by destination name.
	idx := NewIndex(func(k *types.FlowKey) string {
		return k.DestName
	})

	// Add some unique DiachronicFlows to the index.
	// Add them out of order, just to make sure the index is working.
	allFlows := []*types.DiachronicFlow{
		{
			ID: 0,
			Key: types.FlowKey{
				DestName:      "a",
				DestNamespace: "ns1",
			},
		},
		{
			ID: 1,
			Key: types.FlowKey{
				DestName:      "c",
				DestNamespace: "ns1",
			},
		},
		{
			ID: 2,
			Key: types.FlowKey{
				DestName:      "b",
				DestNamespace: "ns1",
			},
		},
		{
			ID: 3,
			Key: types.FlowKey{
				DestName:      "d",
				DestNamespace: "ns1",
			},
		},
	}
	for _, flow := range allFlows {
		idx.Add(flow)
	}

	// Verify the DiachronicFlows are ordered correctly.
	flows := idx.List(IndexFindOpts{})
	Expect(flows).To(HaveLen(4))
	Expect(flows[0].Key.DestName).To(Equal("a"))
	Expect(flows[1].Key.DestName).To(Equal("b"))
	Expect(flows[2].Key.DestName).To(Equal("c"))
	Expect(flows[3].Key.DestName).To(Equal("d"))

	// Remove a DiachronicFlow from the index.
	idx.Remove(&types.DiachronicFlow{
		ID: 2,
		Key: types.FlowKey{
			DestName:      "b",
			DestNamespace: "ns1",
		},
	})

	// Verify the DiachronicFlows are ordered correctly.
	flows = idx.List(IndexFindOpts{})
	Expect(flows).To(HaveLen(3))
	Expect(flows[0].Key.DestName).To(Equal("a"))
	Expect(flows[1].Key.DestName).To(Equal("c"))
	Expect(flows[2].Key.DestName).To(Equal("d"))

	// Add a DiachronicFlow to the index that sorts the same as an existing DiachronicFlow.
	// In this case, we're sorting on DestName, and adding a DiachronicFlow with the same DestName as an existing DiachronicFlow.
	trickyFlow := &types.DiachronicFlow{
		ID: 3,
		Key: types.FlowKey{
			DestName:      "a",
			DestNamespace: "ns2",
		},
	}
	idx.Add(trickyFlow)

	// Verify the DiachronicFlows are ordered correctly. The two flows with the same DestName should be adjacent,
	// sorted by their ID.
	flows = idx.List(IndexFindOpts{})
	Expect(flows).To(HaveLen(4))
	Expect(flows[0].Key.DestName).To(Equal("a"))
	Expect(flows[0].Key.DestNamespace).To(Equal("ns1"))
	Expect(flows[1].Key.DestName).To(Equal("a"))
	Expect(flows[1].Key.DestNamespace).To(Equal("ns2"))
	Expect(flows[2].Key.DestName).To(Equal("c"))
	Expect(flows[3].Key.DestName).To(Equal("d"))

	// Add the same tricky DiachronicFlow again, verify we don't add a duplicate.
	idx.Add(trickyFlow)

	// We should have the same results.
	flows = idx.List(IndexFindOpts{})
	Expect(flows).To(HaveLen(4))
	Expect(flows[0].Key.DestName).To(Equal("a"))
	Expect(flows[0].Key.DestNamespace).To(Equal("ns1"))
	Expect(flows[1].Key.DestName).To(Equal("a"))
	Expect(flows[1].Key.DestNamespace).To(Equal("ns2"))
	Expect(flows[2].Key.DestName).To(Equal("c"))
	Expect(flows[3].Key.DestName).To(Equal("d"))

	// Remove all the original flows from the index, as well as the one we just added.
	for _, flow := range allFlows {
		idx.Remove(flow)
	}
	idx.Remove(trickyFlow)

	// Verify that the index is empty.
	flows = idx.List(IndexFindOpts{})
	Expect(flows).To(HaveLen(0))

	// Remove flows we know aren't in the index, to make sure we're idempotent.
	for _, flow := range allFlows {
		idx.Remove(flow)
	}
}
