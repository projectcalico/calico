// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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

package calc_test

// This file contains canned backend model values for use in tests.  Note the "." import of
// the model package.

import (
	. "github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

// Canned hostnames.

const localHostname = "localhostname"
const remoteHostname = "remotehostname"

// Canned selectors.

var (
	allSelector                 = "all()"
	allSelectorId               = selectorID(allSelector)
	allLessFoobarSelector       = "(all()) && !(foo == 'bar')"
	allLessFoobarSelectorId     = selectorID(allLessFoobarSelector)
	bEpBSelector                = "b == 'b'"
	bEqBSelectorId              = selectorID(bEpBSelector)
	tagSelector                 = "has(tag-1)"
	tagSelectorId               = selectorID(tagSelector)
	tagFoobarSelector           = "tag-1 == 'foobar'"
	tagFoobarSelectorId         = selectorID(tagFoobarSelector)
	namedPortAllTCPID           = namedPortID(allSelector, "tcp", "tcpport")
	namedPortAllLessFoobarTCPID = namedPortID(allLessFoobarSelector, "tcp", "tcpport")
	namedPortAllTCP2ID          = namedPortID(allSelector, "tcp", "tcpport2")
	namedPortAllUDPID           = namedPortID(allSelector, "udp", "udpport")
	inheritSelector             = "profile == 'prof-1'"
	namedPortInheritIPSetID     = namedPortID(inheritSelector, "tcp", "tcpport")
)

// Canned workload endpoints.

var localWlEpKey1 = WorkloadEndpointKey{localHostname, "orch", "wl1", "ep1"}
var remoteWlEpKey1 = WorkloadEndpointKey{remoteHostname, "orch", "wl1", "ep1"}
var localWlEp1Id = "orch/wl1/ep1"
var localWlEpKey2 = WorkloadEndpointKey{localHostname, "orch", "wl2", "ep2"}
var localWlEp2Id = "orch/wl2/ep2"

var localWlEp1 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
	Ports: []EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 1234},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9091},
	},
}

var localWlEp1WithLabelsButNoProfiles = WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
	Ports: []EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 1234},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9091},
	},
}

var localWlEp1WithDupeNamedPorts = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
	Ports: []EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8081},
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8082},
	},
}

var localWlEp1NoProfiles = WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
}

var localWlEp1DifferentIPs = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{mustParseNet("11.0.0.1/32"),
		mustParseNet("11.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe12::1/128"),
		mustParseNet("fc00:fe12::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var ep1IPs = []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // shared with ep2
	"fc00:fe11::2",
}

var localWlEp2 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali2",
	ProfileIDs: []string{"prof-2", "prof-3"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
	Ports: []EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 2345},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9090},
	},
}

var localWlEp2WithLabelsButNoProfiles = WorkloadEndpoint{
	State: "active",
	Name:  "cali2",
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
	Ports: []EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 2345},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9090},
	},
}

var localWlEp2NoProfiles = WorkloadEndpoint{
	State: "active",
	Name:  "cali2",
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128")},
}

var hostEpWithName = HostEndpoint{
	Name:       "eth1",
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.1"),
		mustParseIP("10.0.0.2")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::1"),
		mustParseIP("fc00:fe11::2")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var hostEpWithNamedPorts = HostEndpoint{
	Name:       "eth1",
	ProfileIDs: []string{"prof-1"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.1"),
		mustParseIP("10.0.0.2")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::1"),
		mustParseIP("fc00:fe11::2")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
	Ports: []EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 1234},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9091},
	},
}

var hostEpWithNameKey = HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "named",
}
var hostEpWithNameId = "named"

var hostEp2NoName = HostEndpoint{
	ProfileIDs: []string{"prof-2", "prof-3"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.2"),
		mustParseIP("10.0.0.3")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::2"),
		mustParseIP("fc00:fe11::3")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
}

var hostEp2NoNameKey = HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "unnamed",
}
var hostEpNoNameId = "unnamed"

// Canned tiers/policies.

var order10 = float64(10)
var order20 = float64(20)
var order30 = float64(30)

var policy1_order20 = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var protoTCP = numorstring.ProtocolFromStringV1("tcp")
var protoUDP = numorstring.ProtocolFromStringV1("udp")
var policy1_order20_with_named_port_tcpport = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol: &protoTCP,
			SrcPorts: []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_named_port_tcpport_negated = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol:    &protoTCP,
			NotSrcPorts: []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy_with_named_port_inherit = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol:    &protoTCP,
			SrcSelector: "profile == 'prof-1'",
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []Rule{},
	Types:         []string{"ingress", "egress"},
}

var policy1_order20_with_selector_and_named_port_tcpport = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol:    &protoTCP,
			SrcSelector: allSelector,
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_selector_and_negated_named_port_tcpport = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol:       &protoTCP,
			SrcSelector:    allSelector,
			NotSrcSelector: "foo == 'bar'",
			NotSrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	Types: []string{"ingress"},
}

var policy1_order20_with_selector_and_negated_named_port_tcpport_dest = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol:       &protoTCP,
			DstSelector:    allSelector,
			NotDstSelector: "foo == 'bar'",
			NotDstPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	Types: []string{"ingress"},
}

var policy1_order20_with_selector_and_named_port_udpport = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol:    &protoUDP,
			SrcSelector: allSelector,
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("udpport")},
		},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_named_port_mismatched_protocol = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{
			Protocol: &protoTCP,
			SrcPorts: []numorstring.Port{numorstring.NamedPort("udpport")},
		},
	},
	OutboundRules: []Rule{
		{
			Protocol: &protoUDP,
			SrcPorts: []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_selector_and_named_port_tcpport2 = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{
		{
			Protocol:    &protoTCP,
			SrcSelector: allSelector,
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport2")},
		},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_ingress_only = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	Types: []string{"ingress"},
}

var policy1_order20_egress_only = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"egress"},
}

var policy1_order20_untracked = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	DoNotTrack: true,
}

var policy1_order20_pre_dnat = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	PreDNAT: true,
}

var profileRules1 = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcTag: "tag-1"},
	},
}

var profileRulesWithTagInherit = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: tagSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: tagFoobarSelector},
	},
}

var profileRules1TagUpdate = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{
		{SrcTag: "tag-2"},
	},
}

var profileRules1NegatedTagSelUpdate = ProfileRules{
	InboundRules: []Rule{
		{NotSrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{
		{NotSrcTag: "tag-2"},
	},
}

var profileTags1 = []string{"tag-1"}
var profileLabels1 = map[string]string{
	"profile": "prof-1",
}
var profileLabels2 = map[string]string{
	"profile": "prof-2",
}
var profileLabelsTag1 = map[string]string{
	"tag-1": "foobar",
}

var tag1LabelID = ipSetIDForTag("tag-1")
var tag2LabelID = ipSetIDForTag("tag-2")

var netSet1Key = NetworkSetKey{Name: "netset-1"}
var netSet1 = NetworkSet{
	Nets: []net.IPNet{
		mustParseNet("12.0.0.0/24"),
		mustParseNet("12.0.0.0/24"), // A dupe, why not!
		mustParseNet("12.1.0.0/24"),
		mustParseNet("10.0.0.1/32"), // Overlaps with host endpoint.
		mustParseNet("feed:beef::/32"),
		mustParseNet("feed:beef:0::/32"), // Non-canonical dupe.
	},
	Labels: map[string]string{
		"a": "b",
	},
}
var netSet1WithBEqB = NetworkSet{
	Nets: []net.IPNet{
		mustParseNet("12.0.0.0/24"),
		mustParseNet("12.0.0.0/24"), // A dupe, why not!
		mustParseNet("12.1.0.0/24"),
		mustParseNet("10.0.0.1/32"), // Overlaps with host endpoint.
	},
	Labels: map[string]string{
		"foo": "bar",
		"b":   "b",
	},
}

var netSet2Key = NetworkSetKey{Name: "netset-2"}
var netSet2 = NetworkSet{
	Nets: []net.IPNet{
		mustParseNet("12.0.0.0/24"), // Overlaps with netset-1
		mustParseNet("13.1.0.0/24"),
	},
	Labels: map[string]string{
		"a": "b",
	},
}
