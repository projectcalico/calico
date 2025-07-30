// Copyright (c) 2016-2022 Tigera, Inc. All rights reserved.

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

package labelindex_test

import (
	"fmt"
	"maps"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	. "github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	// No endpoints, parents, etc, should produce no IP sets.
	emptyState = namedPortState{
		Name:                 "empty",
		Endpoints:            map[string]mockEndpoint{},
		Parents:              map[string]mockParent{},
		IPSets:               map[string]ipSet{},
		ExpectedIPSetOutputs: map[string][]string{},
	}

	// baseTests is the "table" for the table-driven tests below.
	// Each entry wraps up a complete set of inputs and expected outputs
	// for the SelectorAndNamedPortIndex.
	baseTests = []namedPortState{
		emptyState,

		{
			Name: "single endpoint single parent a==A",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"aEqualsA": {
					Selector: "a == 'A'",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"aEqualsA": {"10.0.0.1/32"},
			},
		},

		{
			Name:      "no endpoints or parents a==A",
			Endpoints: map[string]mockEndpoint{},
			Parents:   map[string]mockParent{},
			IPSets: map[string]ipSet{
				"aEqualsA": {
					Selector: "a == 'A'",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"aEqualsA": {},
			},
		},

		{
			Name:      "no endpoints single parent",
			Endpoints: map[string]mockEndpoint{},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{},

			ExpectedIPSetOutputs: map[string][]string{},
		},

		{
			Name:      "no endpoints single parent a==A",
			Endpoints: map[string]mockEndpoint{},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"aEqualsA": {
					Selector: "a == 'A'",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"aEqualsA": {},
			},
		},

		{
			Name: "single endpoint single parent has(A)",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA": {"10.0.0.1/32"},
			},
		},

		{
			Name: "two endpoints single parent multiple selectors",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAAndB": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
				},
				"hasB": {
					Selector: "has(b)",
				},
				"hasBAndParentA": {
					// This compares a parent and an endpoint ScanStrategy.
					Selector: "has(b) && has(parentLabelA)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":           {"10.0.0.1/32"},
				"hasAAndB":       {"10.0.0.1/32"},
				"hasB":           {"10.0.0.1/32", "10.0.0.2/32"},
				"hasBAndParentA": {"10.0.0.1/32", "10.0.0.2/32"},
			},
		},

		{
			Name: "multiple endpoints two parents each multiple selectors",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent", "parent2"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32"},
					Ports:    nil,
					Parents:  []string{"parent", "parent2"},
				},
				// Make the full scan strategy less appealing than a parent scan.
				"endpoint3": {Labels: map[string]string{
					"d": "D",
				}},
				"endpoint4": {Labels: map[string]string{
					"d": "D",
				}},
				"endpoint5": {Labels: map[string]string{
					"d": "D",
				}},
				"endpoint6": {Labels: map[string]string{
					"d": "D",
				}},
				"endpoint7": {Labels: map[string]string{
					"d": "D",
				}},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
						"parentLabelC": "C",
					},
				},
				"parent2": {
					Labels: map[string]string{
						"parentLabelB": "B",
						"parentLabelC": "C",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAAndB": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
				},
				"hasB": {
					Selector: "has(b)",
				},
				"hasBAndParentA": {
					// This compares a parent and an endpoint ScanStrategy.
					Selector: "has(b) && has(parentLabelA)",
				},
				"hasBAndParentB": {
					// This compares a parent and an endpoint ScanStrategy.
					Selector: "has(b) && has(parentLabelB)",
				},
				"hasParentC": {
					// This checks scanning multiple parents.
					Selector: "has(parentLabelC)",
				},
				"hasParentAAndParentB": {
					// Checks indexing of parent labels.
					Selector: "has(parentLabelA) && has(parentLabelB)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":                 {"10.0.0.1/32"},
				"hasAAndB":             {"10.0.0.1/32"},
				"hasB":                 {"10.0.0.1/32", "10.0.0.2/32"},
				"hasBAndParentA":       {"10.0.0.1/32", "10.0.0.2/32"},
				"hasBAndParentB":       {"10.0.0.1/32", "10.0.0.2/32"},
				"hasParentC":           {"10.0.0.1/32", "10.0.0.2/32"},
				"hasParentAAndParentB": {"10.0.0.1/32", "10.0.0.2/32"},
			},
		},

		{
			Name: "two endpoints single parent named port selectors",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports: []model.EndpointPort{
						{
							Name:     "http",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     8080,
						},
					},
					Parents: []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32"},
					Ports: []model.EndpointPort{
						{
							Name:     "http",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     8081,
						},
					},
					Parents: []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAHTTP": {
					Selector: "has(a)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
				"hasAAndBHTTP": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
				"hasBHTTP": {
					Selector: "has(b)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
				"hasBAndParentAHTTP": {
					// This compares a parent and an endpoint ScanStrategy.
					Selector: "has(b) && has(parentLabelA)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":               {"10.0.0.1/32"},
				"hasAHTTP":           {"10.0.0.1,tcp:8080"},
				"hasAAndBHTTP":       {"10.0.0.1,tcp:8080"},
				"hasBHTTP":           {"10.0.0.1,tcp:8080", "10.0.0.2,tcp:8081"},
				"hasBAndParentAHTTP": {"10.0.0.1,tcp:8080", "10.0.0.2,tcp:8081"},
			},
		},

		{
			Name: "two endpoints overlapping IPs",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32", "10.0.0.2/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32", "10.0.0.3/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAAndB": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
				},
				"hasB": {
					Selector: "has(b)",
				},
				"hasBAndParentA": {
					// This compares a parent and an endpoint ScanStrategy.
					Selector: "has(b) && has(parentLabelA)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":           {"10.0.0.1/32", "10.0.0.2/32"},
				"hasAAndB":       {"10.0.0.1/32", "10.0.0.2/32"},
				"hasB":           {"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"},
				"hasBAndParentA": {"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"},
			},
		},

		{
			Name: "two endpoints overlapping IPs selectors changed with same ID",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32", "10.0.0.2/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32", "10.0.0.3/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(b)", // Selector swapped with hasB!
				},
				"hasB": {
					Selector: "has(a)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA": {"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"},
				"hasB": {"10.0.0.1/32", "10.0.0.2/32"},
			},
		},

		{
			Name: "two endpoints overlapping IPs named port selectors",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32", "10.0.0.2/32"},
					Ports: []model.EndpointPort{
						{
							Name:     "http",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     8080,
						},
					},
					Parents: []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32", "10.0.0.3/32"},
					Ports: []model.EndpointPort{
						{
							Name:     "http",
							Protocol: numorstring.ProtocolFromString("TCP"),
							Port:     8081,
						},
					},
					Parents: []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAHTTP": {
					Selector: "has(a)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
				"hasAAndBHTTP": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
				"hasBHTTP": {
					Selector: "has(b)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
				"hasBAndParentAHTTP": {
					// This compares a parent and an endpoint ScanStrategy.
					Selector: "has(b) && has(parentLabelA)",
					Protocol: ipsetmember.ProtocolTCP,
					Port:     "http",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":               {"10.0.0.1/32", "10.0.0.2/32"},
				"hasAHTTP":           {"10.0.0.1,tcp:8080", "10.0.0.2,tcp:8080"},
				"hasAAndBHTTP":       {"10.0.0.1,tcp:8080", "10.0.0.2,tcp:8080"},
				"hasBHTTP":           {"10.0.0.1,tcp:8080", "10.0.0.2,tcp:8080", "10.0.0.2,tcp:8081", "10.0.0.3,tcp:8081"},
				"hasBAndParentAHTTP": {"10.0.0.1,tcp:8080", "10.0.0.2,tcp:8080", "10.0.0.2,tcp:8081", "10.0.0.3,tcp:8081"},
			},
		},

		{
			Name: "two endpoints different parents multiple selectors",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32"},
					Ports:    nil,
					Parents:  []string{"parent1"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
				"parent1": {
					Labels: map[string]string{
						"parentLabelB": "B",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAAndB": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
				},
				"hasB": {
					Selector: "has(b)",
				},
				"hasBAndParentA": {
					Selector: "has(b) && has(parentLabelA)",
				},
				"hasBAndParentB": {
					// Should prefer the parent strategy over full scan.
					Selector: "has(b) && has(parentLabelB)",
				},
				"hasParentB": {
					// Should prefer the parent strategy over full scan.
					Selector: "has(parentLabelB)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":           {"10.0.0.1/32"},
				"hasAAndB":       {"10.0.0.1/32"},
				"hasB":           {"10.0.0.1/32", "10.0.0.2/32"},
				"hasBAndParentA": {"10.0.0.1/32"},
				"hasBAndParentB": {"10.0.0.2/32"},
				"hasParentB":     {"10.0.0.2/32"},
			},
		},

		{
			Name: "two endpoints different parents multiple selectors, overlapping IPs",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32", "10.0.0.3/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
				"endpoint2": {
					Labels: map[string]string{
						"b": "B",
						"c": "C",
					},
					RawCIDRs: []string{"10.0.0.2/32", "10.0.0.3/32"},
					Ports:    nil,
					Parents:  []string{"parent1"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
				"parent1": {
					Labels: map[string]string{
						"parentLabelB": "B",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
				"hasAAndB": {
					// This gives more than one ScanStrategy to evaluate.
					Selector: "has(a) && has(b)",
				},
				"hasB": {
					Selector: "has(b)",
				},
				"hasBAndParentA": {
					Selector: "has(b) && has(parentLabelA)",
				},
				"hasBAndParentB": {
					// Should prefer the parent strategy over full scan.
					Selector: "has(b) && has(parentLabelB)",
				},
				"hasParentB": {
					// Should prefer the parent strategy over full scan.
					Selector: "has(parentLabelB)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA":           {"10.0.0.1/32", "10.0.0.3/32"},
				"hasAAndB":       {"10.0.0.1/32", "10.0.0.3/32"},
				"hasB":           {"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"},
				"hasBAndParentA": {"10.0.0.1/32", "10.0.0.3/32"},
				"hasBAndParentB": {"10.0.0.2/32", "10.0.0.3/32"},
				"hasParentB":     {"10.0.0.2/32", "10.0.0.3/32"},
			},
		},

		{
			Name: "endpoint shares label with parent",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"a": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"hasA": {
					Selector: "has(a)",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"hasA": {"10.0.0.1/32"},
			},
		},

		{
			Name: "single endpoint single parent multiple IP sets",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelA": "A",
					},
				},
			},
			IPSets: map[string]ipSet{
				"aEqualsA": {
					Selector: "a == 'A'",
				},
				"hasA": {
					Selector: "has(a)",
				},
				"notA": {
					Selector: "a != 'A'",
				},
				"parentLabelA": {
					Selector: "parentLabelA == 'A'",
				},
				"parentLabelNotA": {
					Selector: "parentLabelA != 'A'",
				},
				"epAndParent": {
					Selector: "a == 'A' && parentLabelA == 'A'",
				},
				"epAndNotParent": {
					Selector: "a == 'A' && parentLabelA != 'A'",
				},
				"notEpAndParent": {
					Selector: "a != 'A' && parentLabelA == 'A'",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"aEqualsA":        {"10.0.0.1/32"},
				"hasA":            {"10.0.0.1/32"},
				"notA":            {},
				"parentLabelA":    {"10.0.0.1/32"},
				"parentLabelNotA": {},
				"epAndParent":     {"10.0.0.1/32"},
				"epAndNotParent":  {},
				"notEpAndParent":  {},
			},
		},

		{
			Name: "single endpoint no parent labels multiple IP sets",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{},
				},
			},
			IPSets: map[string]ipSet{
				"aEqualsA": {
					Selector: "a == 'A'",
				},
				"hasA": {
					Selector: "has(a)",
				},
				"notA": {
					Selector: "a != 'A'",
				},
				"parentLabelA": {
					Selector: "parentLabelA == 'A'",
				},
				"parentLabelNotA": {
					Selector: "parentLabelA != 'A'",
				},
				"epAndParent": {
					Selector: "a == 'A' && parentLabelA == 'A'",
				},
				"epAndNotParent": {
					Selector: "a == 'A' && parentLabelA != 'A'",
				},
				"notEpAndParent": {
					Selector: "a != 'A' && parentLabelA == 'A'",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"aEqualsA":        {"10.0.0.1/32"},
				"hasA":            {"10.0.0.1/32"},
				"notA":            {},
				"parentLabelA":    {},
				"parentLabelNotA": {"10.0.0.1/32"},
				"epAndParent":     {},
				"epAndNotParent":  {"10.0.0.1/32"},
				"notEpAndParent":  {},
			},
		},

		{
			Name: "single endpoint parent label B multiple IP sets",
			Endpoints: map[string]mockEndpoint{
				"endpoint1": {
					Labels: map[string]string{
						"a": "A",
						"b": "B",
					},
					RawCIDRs: []string{"10.0.0.1/32"},
					Ports:    nil,
					Parents:  []string{"parent"},
				},
			},
			Parents: map[string]mockParent{
				"parent": {
					Labels: map[string]string{
						"parentLabelB": "B",
					},
				},
			},
			IPSets: map[string]ipSet{
				"aEqualsA": {
					Selector: "a == 'A'",
				},
				"hasA": {
					Selector: "has(a)",
				},
				"notA": {
					Selector: "a != 'A'",
				},
				"parentLabelA": {
					Selector: "parentLabelA == 'A'",
				},
				"parentLabelNotA": {
					Selector: "parentLabelA != 'A'",
				},
				"epAndParent": {
					Selector: "a == 'A' && parentLabelA == 'A'",
				},
				"epAndNotParent": {
					Selector: "a == 'A' && parentLabelA != 'A'",
				},
				"notEpAndParent": {
					Selector: "a != 'A' && parentLabelA == 'A'",
				},
			},

			ExpectedIPSetOutputs: map[string][]string{
				"aEqualsA":        {"10.0.0.1/32"},
				"hasA":            {"10.0.0.1/32"},
				"notA":            {},
				"parentLabelA":    {},
				"parentLabelNotA": {"10.0.0.1/32"},
				"epAndParent":     {},
				"epAndNotParent":  {"10.0.0.1/32"},
				"notEpAndParent":  {},
			},
		},
	}
)

func TestNamedPortIndex(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	log.SetLevel(log.DebugLevel)

	for _, state := range baseTests {
		// First run each base test as-is: just apply its inputs and
		// check that we get the right output.
		t.Run("Base "+state.Name, func(t *testing.T) {
			idx := NewSelectorAndNamedPortIndex(false)
			RegisterTestingT(t)
			rec := newRecorder()
			idx.OnMemberAdded = rec.OnMemberAdded
			idx.OnMemberRemoved = rec.OnMemberRemoved
			applyStateTransition(idx, rec, emptyState, state, "normal")
			state.CheckRecordedState(t, rec)
		})
	}

	var generatedTests [][]namedPortState
	for i, s1 := range baseTests {
		for j, s2 := range baseTests {
			if i == j {
				continue
			}
			generatedTests = append(generatedTests, []namedPortState{s1, s2})
		}
	}

	for _, applyStrategy := range applyStrategies {
		t.Run(applyStrategy, func(t *testing.T) {
			for _, states := range generatedTests {
				var names []string
				for _, s := range states {
					names = append(names, s.Name)
				}
				t.Run(strings.Join(names, " THEN "),
					func(t *testing.T) {
						logutils.ConfigureLoggingForTestingT(t)
						RegisterTestingT(t)
						idx := NewSelectorAndNamedPortIndex(false)
						rec := newRecorder()
						idx.OnMemberAdded = rec.OnMemberAdded
						idx.OnMemberRemoved = rec.OnMemberRemoved

						lastState := emptyState
						for _, state := range states {
							applyStateTransition(idx, rec, lastState, state, applyStrategy)
							lastState = state
							state.CheckRecordedState(t, rec)
						}
					})
			}
		})
	}
}

var applyStrategies = []string{"normal", "reverse"}

// namedPortState represents a particular state of the named port index;
// both the input endpoints and expected IP sets that it should output in that
// state.
type namedPortState struct {
	Name string

	Endpoints map[string]mockEndpoint
	Parents   map[string]mockParent
	IPSets    map[string]ipSet

	ExpectedIPSetOutputs map[string][]string
}

func (s namedPortState) CheckRecordedState(t *testing.T, rec *testRecorder) {
	t.Helper()
	log.Infof("TEST HARNESS: Checking recorded state (%s)", s.Name)
	for _, setName := range slices.Sorted(maps.Keys(s.ExpectedIPSetOutputs)) {
		expected := s.ExpectedIPSetOutputs[setName]
		setName := "s:" + setName
		memberStrings := set.New[string]()
		for m := range rec.ipsets[setName] {
			memberStrings.Add(m.ToProtobufFormat())
		}
		ExpectWithOffset(1, memberStrings).To(Equal(set.FromArray(expected)),
			fmt.Sprintf("%s: expected IP set %s to have entries: %v, not %v, all: %v", s.Name, setName, expected, memberStrings.Slice(), rec.ipsets))
	}
	for setName, members := range rec.ipsets {
		if _, ok := s.ExpectedIPSetOutputs[strings.TrimPrefix(setName, "s:")]; ok {
			continue
		}
		ExpectWithOffset(1, members).To(HaveLen(0), "Unexpected IP set: "+setName)
	}
	log.Infof("TEST HARNESS: Recorded state looks good.")
}

// mockEndpoint represents an abstract endpoint or network set.
type mockEndpoint struct {
	Labels   map[string]string
	RawCIDRs []string
	Ports    []model.EndpointPort
	Parents  []string
}

func (e mockEndpoint) CIDRs() (out []ip.CIDR) {
	for _, raw := range e.RawCIDRs {
		out = append(out, ip.MustParseCIDROrIP(raw))
	}
	return
}

type mockParent struct {
	Labels map[string]string
}

type ipSet struct {
	Selector string
	Protocol ipsetmember.Protocol
	Port     string
}

func (s ipSet) ParsedSelector() *selector.Selector {
	sel, err := selector.Parse(s.Selector)
	Expect(err).NotTo(HaveOccurred())
	return sel
}

// applyStateTransition sends updates to the SelectorAndNamedPortIndex to
// move it from state s1 to state s2.  For example if s2 has an endpoint that
// doesn't appear in s1, it will call UpdateEndpointOrSet to add it.  If s2
// does not have an endpoint that is in s1, it will call DeleteEndpoint and so
// on.
//
// The strategy argument allows for the order of update operations to be
// reversed.
func applyStateTransition(idx *SelectorAndNamedPortIndex, rec *testRecorder, s1, s2 namedPortState, strategy string) {
	log.Infof("TEST HARNESS: Moving from state %q to state %q", s1.Name, s2.Name)

	// We collect all the operations that we want to do in this slice,
	// then we apply then according to the strategy at the end.
	var ops []func()

	// Endpoint updates and deletions...
	for k, ep := range s2.Endpoints {
		if reflect.DeepEqual(s1.Endpoints[k], ep) {
			// No change
			log.Infof("TEST HARNESS: Skip updating unchanged endpoint/set %v", k)
			continue
		}
		k := k
		ep := ep
		ops = append(ops, func() {
			log.Infof("TEST HARNESS: Updating endpoint/set %v", k)
			idx.UpdateEndpointOrSet(k, uniquelabels.Make(ep.Labels), ep.CIDRs(), ep.Ports, ep.Parents)
		})
	}
	for k := range s1.Endpoints {
		if _, ok := s2.Endpoints[k]; ok {
			continue
		}
		k := k
		ops = append(ops, func() {
			log.Infof("TEST HARNESS: Deleting endpoint/set %v", k)
			idx.DeleteEndpoint(k)
		})
	}

	// Parent updates and deletions...
	dupeDone := false
	for k, p := range s2.Parents {
		if reflect.DeepEqual(s1.Parents[k], p) {
			// No change
			continue
		}
		k := k
		p := p
		ops = append(ops, func() {
			log.Infof("TEST HARNESS: Updating parent labels %v -> %v", k, p.Labels)
			idx.UpdateParentLabels(k, p.Labels)
		})
		if !dupeDone {
			ops = append(ops, func() {
				log.Infof("TEST HARNESS: Updating parent labels (dupe) %v -> %v", k, p.Labels)
				idx.UpdateParentLabels(k, p.Labels)
			})
			dupeDone = true
		}
	}
	for k := range s1.Parents {
		if _, ok := s2.Parents[k]; ok {
			continue
		}
		k := k
		ops = append(ops, func() {
			log.Infof("TEST HARNESS: Delete parent labels %v", k)
			idx.DeleteParentLabels(k)
		})
	}

	// IP set updates and deletions...
	dupeDone = false
	for k, s := range s2.IPSets {
		if reflect.DeepEqual(s1.IPSets[k], s) {
			// No change
			continue
		}
		k := k
		s := s
		ipSetID := "s:" + k
		ops = append(ops, func() {
			log.Infof("TEST HARNESS: Update IP set %v -> %s", k, s.Selector)
			idx.UpdateIPSet(ipSetID, s.ParsedSelector(), s.Protocol, s.Port)
		})
		if !dupeDone {
			// For coverage of "unchanged IP set" case.
			ops = append(ops, func() {
				log.Infof("TEST HARNESS: Update IP set (dupe) %v -> %s", k, s.Selector)
				idx.UpdateIPSet(ipSetID, s.ParsedSelector(), s.Protocol, s.Port)
			})
			dupeDone = true
		}
	}
	dupeDone = false
	for k := range s1.IPSets {
		if _, ok := s2.IPSets[k]; ok {
			continue
		}
		k := k
		ipSetID := "s:" + k
		ops = append(ops, func() {
			log.Infof("TEST HARNESS: Delete IP set %v", ipSetID)
			idx.DeleteIPSet(ipSetID)
		})
		if !dupeDone {
			ops = append(ops, func() {
				log.Infof("TEST HARNESS: Delete IP set (dupe) %v", ipSetID)
				idx.DeleteIPSet(ipSetID)
			})
			dupeDone = true
		}
	}

	// Apply the updates.
	if strategy == "reverse" {
		for i := len(ops) - 1; i >= 0; i-- {
			ops[i]()
		}
	} else {
		for _, op := range ops {
			op()
		}
	}

	// The named port index doesn't emit per-member deletions since
	// the downstream component in the calc graph doesn't need that.
	// Simulate the whole-IP set deletion.
	for k := range s1.IPSets {
		if _, ok := s2.IPSets[k]; ok {
			continue
		}
		ipSetID := "s:" + k
		delete(rec.ipsets, ipSetID)
	}
}

var _ = Describe("MemberDeduplicator", func() {
	var d OverlapSuppressor
	BeforeEach(func() {
		d = NewMemberOverlapSuppressor()
	})

	It("should handle adding, masking, and removing members in the same IP set", func() {
		// Add an IP.
		By("Adding an IP")
		ip1 := ip.MustParseCIDROrIP("10.0.0.1/32")
		add, removes := d.Add("setA", ip1)
		Expect(add).To(Equal(ip1))
		Expect(removes).To(HaveLen(0))

		// Add the same IP again - it should have no effect.
		add, removes = d.Add("setA", ip1)
		Expect(add).To(BeNil())
		Expect(removes).To(HaveLen(0))

		// Add a second IP in a different CIDR, as well as another IP within the CIDR.
		ip2 := ip.MustParseCIDROrIP("10.0.0.2/32")
		add, removes = d.Add("setA", ip2)
		Expect(add).To(Equal(ip2))
		Expect(removes).To(HaveLen(0))

		ip3 := ip.MustParseCIDROrIP("11.0.0.2/32")
		add, removes = d.Add("setA", ip3)
		Expect(add).To(Equal(ip3))
		Expect(removes).To(HaveLen(0))

		// Mask the IP - we expect the new CIDR to be advertised,
		// and the old IPs in the CIDR to be withdrawn since it is covered by the new CIDR.
		By("Masking the IP")
		maskingCIDR := ip.MustParseCIDROrIP("10.0.0.0/24")
		add, removes = d.Add("setA", maskingCIDR)
		Expect(add).To(Equal(maskingCIDR))
		Expect(removes).To(ConsistOf(ip1, ip2))

		// Add another IP within the CIDR - it should not be added, since it is masked.
		ip4 := ip.MustParseCIDROrIP("10.0.0.3/32")
		add, removes = d.Add("setA", ip4)
		Expect(add).To(BeNil())
		Expect(removes).To(HaveLen(0))

		// Remove the CIDR - expect the previously masked IPs to be re-added.
		remove, adds := d.Remove("setA", maskingCIDR)
		Expect(remove).To(Equal(maskingCIDR))
		Expect(adds).To(ConsistOf(ip1, ip2, ip4))
	})

	It("should support dual stack IP sets", func() {
		ip1 := ip.MustParseCIDROrIP("10.0.0.1/32")
		ip2 := ip.MustParseCIDROrIP("fe80:dead:beef::0/122")
		add, removes := d.Add("setA", ip1)
		Expect(add).To(Equal(ip1))
		Expect(removes).To(HaveLen(0))
		add, removes = d.Add("setA", ip2)
		Expect(add).To(Equal(ip2))
		Expect(removes).To(HaveLen(0))
	})

	It("should support deleting an IP set", func() {
		ip1 := ip.MustParseCIDROrIP("10.0.0.1/32")
		add, removes := d.Add("setA", ip1)
		Expect(add).To(Equal(ip1))
		Expect(removes).To(HaveLen(0))
		d.DeleteIPSet("setA")
		add, removes = d.Add("setA", ip1)
		Expect(add).To(Equal(ip1))
		Expect(removes).To(HaveLen(0))
	})

	It("should handle multiple IP set with overlapping members", func() {
		ip1 := ip.MustParseCIDROrIP("10.0.0.1/32")
		ip2 := ip.MustParseCIDROrIP("10.0.0.2/32")
		maskingCIDR := ip.MustParseCIDROrIP("10.0.0.0/24")

		// Add each IP to a different IP set.
		add, removes := d.Add("setA", ip1)
		Expect(add).To(Equal(ip1))
		Expect(removes).To(HaveLen(0))
		add, removes = d.Add("setB", ip2)
		Expect(add).To(Equal(ip2))
		Expect(removes).To(HaveLen(0))

		// Mask setA. It should only recall ip1.
		add, removes = d.Add("setA", maskingCIDR)
		Expect(add).To(Equal(maskingCIDR))
		Expect(removes).To(ConsistOf(ip1))

		// Mask setB.
		add, removes = d.Add("setB", maskingCIDR)
		Expect(add).To(Equal(maskingCIDR))
		Expect(removes).To(ConsistOf(ip2))
	})

	It("should handle descendants on different tiers of the underlying trie", func() {
		ip1 := ip.MustParseCIDROrIP("10.0.1.1/32")         // End of the trie
		ip2 := ip.MustParseCIDROrIP("10.0.2.1/32")         // End of the trie
		ip3 := ip.MustParseCIDROrIP("10.0.1.0/24")         // Masks ip1
		maskingCIDR := ip.MustParseCIDROrIP("10.0.0.0/16") // Masks all of the above.

		// Add each IP to the same set.
		add, removes := d.Add("setA", ip1)
		Expect(add).To(Equal(ip1))
		Expect(removes).To(HaveLen(0))
		add, removes = d.Add("setA", ip2)
		Expect(add).To(Equal(ip2))
		Expect(removes).To(HaveLen(0))
		add, removes = d.Add("setA", ip3)
		Expect(add).To(Equal(ip3))
		Expect(removes).To(ConsistOf(ip1)) // ip1 is masked by ip3.
		add, removes = d.Add("setA", maskingCIDR)
		Expect(add).To(Equal(maskingCIDR))
		Expect(removes).To(ConsistOf(ip2, ip3)) // ip2 and ip3 are masked by maskingCIDR, ip1 is already masked.

		// Removing the masking CIDR should bring back ip2 and ip3.
		remove, adds := d.Remove("setA", maskingCIDR)
		Expect(remove).To(Equal(maskingCIDR))
		Expect(adds).To(ConsistOf(ip2, ip3))

		// Removing ip3 should bring back ip1.
		remove, adds = d.Remove("setA", ip3)
		Expect(remove).To(Equal(ip3))
		Expect(adds).To(ConsistOf(ip1))
	})
})

var _ = Describe("SelectorAndNamedPortIndex", func() {
	var uut *SelectorAndNamedPortIndex
	var recorder *testRecorder

	BeforeEach(func() {
		uut = NewSelectorAndNamedPortIndex(false)
		recorder = newRecorder()
		uut.OnMemberAdded = recorder.OnMemberAdded
		uut.OnMemberRemoved = recorder.OnMemberRemoved
	})

	Describe("NetworkSet CIDRs", func() {
		It("should include equivalent CIDRs only once", func() {
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.NetworkSetKey{Name: "blinky"},
					Value: &model.NetworkSet{
						Nets: []calinet.IPNet{
							{IPNet: net.IPNet{
								IP:   net.IP{192, 168, 4, 10},
								Mask: net.IPMask{255, 255, 0, 0},
							}},
						},
						Labels: uniquelabels.Make(map[string]string{"villain": "ghost"}),
					},
				},
			})
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.NetworkSetKey{Name: "inky"},
					Value: &model.NetworkSet{
						Nets: []calinet.IPNet{
							{IPNet: net.IPNet{
								IP:   net.IP{192, 168, 20, 1},
								Mask: net.IPMask{255, 255, 0, 0},
							}},
						},
						Labels: uniquelabels.Make(map[string]string{"villain": "ghost"}),
					},
				},
			})
			s, err := selector.Parse("villain == 'ghost'")
			Expect(err).ToNot(HaveOccurred())
			uut.UpdateIPSet("villains", s, ipsetmember.ProtocolNone, "")
			set, ok := recorder.ipsets["villains"]
			Expect(ok).To(BeTrue())
			Expect(set).To(HaveLen(1))
		})
	})

	Describe("NetworkSet profiles", func() {
		It("should inherit labels from profiles", func() {
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindProfile, Name: "doo"},
					Value: &v3.Profile{
						Spec: v3.ProfileSpec{
							LabelsToApply: map[string]string{"superhero": "scooby"},
						},
					},
				},
			})
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.NetworkSetKey{Name: "scary-ns"},
					Value: &model.NetworkSet{
						Nets: []calinet.IPNet{
							{IPNet: net.IPNet{
								IP:   net.IP{192, 168, 20, 1},
								Mask: net.IPMask{255, 255, 0, 0},
							}},
						},
						Labels:     uniquelabels.Make(map[string]string{"villain": "ghost"}),
						ProfileIDs: []string{"doo"},
					},
				},
			})
			s, err := selector.Parse("villain == 'ghost' && superhero == 'scooby'")
			Expect(err).ToNot(HaveOccurred())
			uut.UpdateIPSet("scoobydoobydoo", s, ipsetmember.ProtocolNone, "")
			set, ok := recorder.ipsets["scoobydoobydoo"]
			Expect(ok).To(BeTrue())
			Expect(set).To(HaveLen(1))
		})
	})
	Describe("HostEndpoint CIDRs", func() {
		It("should update IP sets for labels with empty values", func() {
			hep := &model.HostEndpoint{
				Name:              "eth0",
				ExpectedIPv4Addrs: []calinet.IP{calinet.MustParseIP("1.2.3.4")},
				ExpectedIPv6Addrs: []calinet.IP{calinet.MustParseIP("aa:bb::cc:dd")},
				Labels: uniquelabels.Make(map[string]string{
					"label2": "",
				}),
				ProfileIDs: []string{"profile1"},
			}
			hepKVP := model.KVPair{
				Key:   model.HostEndpointKey{Hostname: "127.0.0.1", EndpointID: "hosta.eth0-a"},
				Value: hep,
			}
			uut.OnUpdate(api.Update{KVPair: hepKVP})
			s, err := selector.Parse("has(label2)")
			Expect(err).ToNot(HaveOccurred())

			// The new ipset should have 2 IPs.
			uut.UpdateIPSet("heptest", s, ipsetmember.ProtocolNone, "")
			set, ok := recorder.ipsets["heptest"]
			Expect(ok).To(BeTrue())
			Expect(set).To(HaveLen(2))

			// Update the hostendpoint labels so they are not matched by the
			// selector.
			hep.Labels = uniquelabels.Make(map[string]string{
				"label1": "value1",
			})
			uut.OnUpdate(api.Update{KVPair: hepKVP})

			// Expect the ipset to be empty (OnMemberRemoved will have been
			// called twice.)
			set, ok = recorder.ipsets["heptest"]
			Expect(ok).To(BeFalse())
			Expect(set).To(HaveLen(0))
		})
	})
})

func newRecorder() *testRecorder {
	return &testRecorder{ipsets: make(map[string]map[ipsetmember.IPSetMember]bool)}
}

type testRecorder struct {
	ipsets map[string]map[ipsetmember.IPSetMember]bool
}

func (t *testRecorder) OnMemberAdded(ipSetID string, member ipsetmember.IPSetMember) {
	s := t.ipsets[ipSetID]
	if s == nil {
		s = make(map[ipsetmember.IPSetMember]bool)
		t.ipsets[ipSetID] = s
	}
	s[member] = true
}

func (t *testRecorder) OnMemberRemoved(ipSetID string, member ipsetmember.IPSetMember) {
	s := t.ipsets[ipSetID]
	delete(s, member)
	if len(s) == 0 {
		delete(t.ipsets, ipSetID)
	}
}
