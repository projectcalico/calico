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
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type simpleLogAggregatorStub struct {
	diachronics []*types.DiachronicFlow
}

func (l simpleLogAggregatorStub) flowSet(startGt, startLt int64) set.Set[types.FlowKey] {
	s := set.New[types.FlowKey]()
	for _, d := range l.diachronics {
		if d.Within(startGt, startLt) {
			s.Add(d.Key)
		}
	}
	return s
}

func (l simpleLogAggregatorStub) diachronicFlow(key types.FlowKey) *types.DiachronicFlow {
	for _, d := range l.diachronics {
		if d.Key == key {
			return d
		}
	}
	return nil
}

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

	data := &types.Flow{
		PacketsIn:               1,
		PacketsOut:              1,
		BytesIn:                 1,
		BytesOut:                1,
		NumConnectionsLive:      1,
		NumConnectionsStarted:   1,
		NumConnectionsCompleted: 1,
	}

	for _, flow := range allFlows {
		// Make sure each one has some data in it.
		flow.AddFlow(data, 0, 1)
		idx.Add(flow)
	}

	// Verify the DiachronicFlows are ordered correctly.
	flows, _ := idx.List(IndexFindOpts{})
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
	flows, _ = idx.List(IndexFindOpts{})
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
	trickyFlow.AddFlow(data, 0, 1)
	idx.Add(trickyFlow)

	// Verify the DiachronicFlows are ordered correctly. The two flows with the same DestName should be adjacent,
	// sorted by their ID.
	flows, _ = idx.List(IndexFindOpts{})
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
	flows, _ = idx.List(IndexFindOpts{})
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
	flows, _ = idx.List(IndexFindOpts{})
	Expect(flows).To(HaveLen(0))

	// Remove flows we know aren't in the index, to make sure we're idempotent.
	for _, flow := range allFlows {
		idx.Remove(flow)
	}
}

func TestIndexPagination_General(t *testing.T) {
	defer setupTest(t)()

	allFlows := []*types.DiachronicFlow{
		{
			ID:  0,
			Key: types.FlowKey{DestName: "a", DestNamespace: "ns1"},
		},
		{
			ID:  1,
			Key: types.FlowKey{DestName: "c", DestNamespace: "ns1"},
		},
		{
			ID:  2,
			Key: types.FlowKey{DestName: "b", DestNamespace: "ns1"},
		},
		{
			ID:  3,
			Key: types.FlowKey{DestName: "d", DestNamespace: "ns1"},
		},
		{
			ID:  4,
			Key: types.FlowKey{DestName: "e", DestNamespace: "ns2"},
		},
		{
			ID:  5,
			Key: types.FlowKey{DestName: "f", DestNamespace: "ns2"},
		},
		{
			ID:  6,
			Key: types.FlowKey{DestName: "g", DestNamespace: "ns2"},
		},
		{
			ID:  7,
			Key: types.FlowKey{DestName: "h", DestNamespace: "ns2"},
		},
		{
			ID:  8,
			Key: types.FlowKey{DestName: "i", DestNamespace: "ns3"},
		},
	}

	data := &types.Flow{
		PacketsIn:               1,
		PacketsOut:              1,
		BytesIn:                 1,
		BytesOut:                1,
		NumConnectionsLive:      1,
		NumConnectionsStarted:   1,
		NumConnectionsCompleted: 1,
	}

	// Create an index, ordered by destination name.
	idx := NewIndex(func(k *types.FlowKey) string {
		return k.DestName
	})

	for _, flow := range allFlows {
		// Make sure each one has some data in it.
		flow.AddFlow(data, 0, 1)
		idx.Add(flow)
	}

	tt := []struct {
		description      string
		page             int64
		pageSize         int64
		expectedPages    int
		expectedNumFlows int
		filter           *proto.Filter
	}{
		{
			description:      "page 0, limit 1",
			page:             0,
			pageSize:         1,
			expectedPages:    9,
			expectedNumFlows: 1,
		},
		{
			description:      "page 0, limit 2",
			page:             0,
			pageSize:         2,
			expectedPages:    5,
			expectedNumFlows: 2,
		},
		{
			description:      "page 0, limit 2",
			page:             0,
			pageSize:         2,
			expectedPages:    2,
			expectedNumFlows: 2,
			filter:           &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns2"}}},
		},
		{
			description:      "page 0, size 0",
			page:             0,
			pageSize:         0,
			expectedPages:    1,
			expectedNumFlows: 4,
			filter:           &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns2"}}},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			RegisterTestingT(t)
			flows, totalPages := idx.List(IndexFindOpts{
				pageSize: tc.pageSize,
				page:     tc.page,
				filter:   tc.filter,
			})
			Expect(totalPages).To(Equal(tc.expectedPages))
			Expect(len(flows)).To(Equal(tc.expectedNumFlows))
		})
	}
}

func TestIndexPagination_KeyOnly(t *testing.T) {
	defer setupTest(t)()

	newFlowKey := func(name, ns string) types.FlowKey {
		return types.FlowKey{DestName: name, DestNamespace: ns}
	}

	data := &types.Flow{
		PacketsIn:               1,
		PacketsOut:              1,
		BytesIn:                 1,
		BytesOut:                1,
		NumConnectionsLive:      1,
		NumConnectionsStarted:   1,
		NumConnectionsCompleted: 1,
	}

	tt := []struct {
		description      string
		flowKeys         []types.FlowKey
		page             int64
		pageSize         int64
		expectedPages    int
		expectedNumFlows int
		filter           *proto.Filter
	}{
		{
			description: "page 0, limit 1",
			flowKeys: []types.FlowKey{
				newFlowKey("a", "ns1"),
				newFlowKey("a", "ns2"),
				newFlowKey("b", "ns1"),
				newFlowKey("c", "ns1"),
				newFlowKey("d", "ns1"),
				newFlowKey("d", "ns2"),
			},
			page:             0,
			pageSize:         1,
			expectedPages:    4,
			expectedNumFlows: 1,
		},
		{
			description: "page 0, limit 1",
			flowKeys: []types.FlowKey{
				newFlowKey("a", "ns1"),
				newFlowKey("a", "ns2"),
				newFlowKey("b", "ns1"),
				newFlowKey("c", "ns1"),
				newFlowKey("d", "ns1"),
				newFlowKey("d", "ns2"),
			},
			page:             1,
			pageSize:         2,
			expectedPages:    2,
			expectedNumFlows: 2,
		},
		{
			description: "page 0, size 0",
			flowKeys: []types.FlowKey{
				newFlowKey("a", "ns1"),
				newFlowKey("a", "ns2"),
				newFlowKey("b", "ns1"),
				newFlowKey("c", "ns1"),
				newFlowKey("d", "ns1"),
				newFlowKey("d", "ns2"),
			},
			page:             0,
			pageSize:         0,
			expectedPages:    1,
			expectedNumFlows: 4,
		},
		{
			description: "page 0, size 0 with no matching matching flows",
			flowKeys: []types.FlowKey{
				newFlowKey("a", "ns1"),
				newFlowKey("b", "ns2"),
			},
			filter:           &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "noexisty"}}},
			page:             0,
			pageSize:         0,
			expectedPages:    0,
			expectedNumFlows: 0,
		},
		{
			description: "page 1, size 2 with a filter",
			flowKeys: []types.FlowKey{
				newFlowKey("a", "ns1"),
				newFlowKey("b", "ns1"),
				newFlowKey("c", "ns1"),
				newFlowKey("d", "ns2"),
			},
			filter:           &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns1"}}},
			page:             1,
			pageSize:         2,
			expectedPages:    2,
			expectedNumFlows: 1,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			RegisterTestingT(t)
			var allFlows []*types.DiachronicFlow
			for i, key := range tc.flowKeys {
				allFlows = append(allFlows, &types.DiachronicFlow{
					ID:  int64(i),
					Key: key,
				})
			}

			idx := NewIndex(func(k *types.FlowKey) string {
				return k.DestName
			})

			for _, flow := range allFlows {
				// Make sure each one has some data in it.
				flow.AddFlow(data, 0, 1)
				idx.Add(flow)
			}

			keys, totalPages := idx.Keys(IndexFindOpts{
				pageSize: tc.pageSize,
				page:     tc.page,
				filter:   tc.filter,
			})
			Expect(totalPages).To(Equal(tc.expectedPages))
			Expect(len(keys)).To(Equal(tc.expectedNumFlows))
		})
	}
}

func TestRingIndexPagination_General(t *testing.T) {
	defer setupTest(t)()

	allFlows := []*types.DiachronicFlow{
		{
			ID:      0,
			Key:     types.FlowKey{DestName: "a", DestNamespace: "ns1"},
			Windows: []types.Window{},
		},
		{
			ID:  1,
			Key: types.FlowKey{DestName: "c", DestNamespace: "ns1"},
		},
		{
			ID:  2,
			Key: types.FlowKey{DestName: "b", DestNamespace: "ns1"},
		},
		{
			ID:  3,
			Key: types.FlowKey{DestName: "d", DestNamespace: "ns1"},
		},
		{
			ID:  4,
			Key: types.FlowKey{DestName: "e", DestNamespace: "ns2"},
		},
		{
			ID:  5,
			Key: types.FlowKey{DestName: "f", DestNamespace: "ns2"},
		},
		{
			ID:  6,
			Key: types.FlowKey{DestName: "g", DestNamespace: "ns2"},
		},
		{
			ID:  7,
			Key: types.FlowKey{DestName: "h", DestNamespace: "ns2"},
		},
		{
			ID:  8,
			Key: types.FlowKey{DestName: "i", DestNamespace: "ns3"},
		},
	}

	data := &types.Flow{
		PacketsIn:               1,
		PacketsOut:              1,
		BytesIn:                 1,
		BytesOut:                1,
		NumConnectionsLive:      1,
		NumConnectionsStarted:   1,
		NumConnectionsCompleted: 1,
	}

	// Create an index, ordered by destination name.

	flowSet := set.New[types.FlowKey]()
	for _, flow := range allFlows {
		flow.AddFlow(data, 0, 1)
		flowSet.Add(flow.Key)
	}

	agg := &simpleLogAggregatorStub{diachronics: allFlows}
	idx := NewRingIndex(agg)

	tt := []struct {
		description      string
		page             int64
		pageSize         int64
		expectedPages    int
		expectedNumFlows int
		filter           *proto.Filter
	}{
		{
			description:      "page 0, limit 1",
			page:             0,
			pageSize:         1,
			expectedPages:    9,
			expectedNumFlows: 1,
		},
		{
			description:      "page 0, limit 2",
			page:             0,
			pageSize:         2,
			expectedPages:    5,
			expectedNumFlows: 2,
		},
		{
			description:      "page 0, limit 2",
			page:             0,
			pageSize:         2,
			expectedPages:    2,
			expectedNumFlows: 2,
			filter:           &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns2"}}},
		},
		{
			description:      "page 0, limit 0",
			page:             0,
			pageSize:         0,
			expectedPages:    1,
			expectedNumFlows: 4,
			filter:           &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns2"}}},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			RegisterTestingT(t)
			flows, totalPages := idx.List(IndexFindOpts{
				startTimeGt: -0,
				startTimeLt: 2,
				pageSize:    tc.pageSize,
				page:        tc.page,
				filter:      tc.filter,
			})
			Expect(totalPages).To(Equal(tc.expectedPages))
			Expect(len(flows)).To(Equal(tc.expectedNumFlows))
		})
	}
}
