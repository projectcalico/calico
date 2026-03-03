// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Canned hostnames.
var (
	localHostname   = "localhostname"
	remoteHostname  = "remotehostname"
	remoteHostname2 = "remotehostname2"
)

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
	httpMatchMethod             = model.HTTPMatch{Methods: []string{"GET"}}
	serviceAccountSelector      = "name == 'sa1'"
)

// Canned workload endpoints.

var (
	localWlEpKey1 = model.WorkloadEndpointKey{Hostname: localHostname, OrchestratorID: "orch", WorkloadID: "wl1", EndpointID: "ep1"}
	localWlEp1Id  = "orch/wl1/ep1"
	localWlEpKey2 = model.WorkloadEndpointKey{Hostname: localHostname, OrchestratorID: "orch", WorkloadID: "wl2", EndpointID: "ep2"}
	localWlEp2Id  = "orch/wl2/ep2"
)

// A remote workload endpoint
var remoteWlEpKey1 = model.WorkloadEndpointKey{Hostname: remoteHostname, OrchestratorID: "orch", WorkloadID: "wl1", EndpointID: "ep1"}

// Same as remoteWlEpKey1 but on a different host.
var remoteWlEpKey2 = model.WorkloadEndpointKey{Hostname: remoteHostname2, OrchestratorID: "orch", WorkloadID: "wl1", EndpointID: "ep1"}

var localWlEp1 = model.WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	}),
	Ports: []model.EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 1234},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9091},
	},
}

var localWlEp1WithLabelsButNoProfiles = model.WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	}),
	Ports: []model.EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 1234},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9091},
	},
}

var localWlEp1WithDupeNamedPorts = model.WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	}),
	Ports: []model.EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8081},
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8082},
	},
}

var localWlEp1NoProfiles = model.WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128"),
	},
}

var localWlEp1DifferentIPs = model.WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{
		mustParseNet("11.0.0.1/32"),
		mustParseNet("11.0.0.2/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe12::1/128"),
		mustParseNet("fc00:fe12::2/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	}),
}

var ep1IPs = []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // shared with ep2
	"fc00:fe11::2/128",
}

var localWlEp2 = model.WorkloadEndpoint{
	State:      "active",
	Name:       "cali2",
	ProfileIDs: []string{"prof-2", "prof-3"},
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	}),
	Ports: []model.EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 2345},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9090},
	},
}

var localWlEp2WithLabelsButNoProfiles = model.WorkloadEndpoint{
	State: "active",
	Name:  "cali2",
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	}),
	Ports: []model.EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 2345},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9090},
	},
}

var localWlEp2NoProfiles = model.WorkloadEndpoint{
	State: "active",
	Name:  "cali2",
	IPv4Nets: []net.IPNet{
		mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32"),
	},
	IPv6Nets: []net.IPNet{
		mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128"),
	},
}

var remoteWlEp1 = model.WorkloadEndpoint{
	State:      "active",
	Name:       "remote-wep-1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets:   []net.IPNet{mustParseNet("10.0.0.5/32")},
	Labels: uniquelabels.Make(map[string]string{
		"id": "rem-ep-1",
	}),
}

var remoteWlEp1DualStack = model.WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets:   []net.IPNet{mustParseNet("10.1.0.1/32"), mustParseNet("10.1.0.2/32")},
	IPv6Nets:   []net.IPNet{mustParseNet("fe80:fe11::1/128"), mustParseNet("fe80:fe11::2/128")},
	Labels: uniquelabels.Make(map[string]string{
		"id": "rem-ep-1",
		"x":  "x",
		"y":  "y",
	}),
}

var hostEpWithName = model.HostEndpoint{
	Name:       "eth1",
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	ExpectedIPv4Addrs: []net.IP{
		mustParseIP("10.0.0.1"),
		mustParseIP("10.0.0.2"),
	},
	ExpectedIPv6Addrs: []net.IP{
		mustParseIP("fc00:fe11::1"),
		mustParseIP("fc00:fe11::2"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	}),
}

var hostEpWithNamedPorts = model.HostEndpoint{
	Name:       "eth1",
	ProfileIDs: []string{"prof-1"},
	ExpectedIPv4Addrs: []net.IP{
		mustParseIP("10.0.0.1"),
		mustParseIP("10.0.0.2"),
	},
	ExpectedIPv6Addrs: []net.IP{
		mustParseIP("fc00:fe11::1"),
		mustParseIP("fc00:fe11::2"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	}),
	Ports: []model.EndpointPort{
		{Name: "tcpport", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 8080},
		{Name: "tcpport2", Protocol: numorstring.ProtocolFromStringV1("tcp"), Port: 1234},
		{Name: "udpport", Protocol: numorstring.ProtocolFromStringV1("udp"), Port: 9091},
	},
}

var hostEpWithNameKey = model.HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "named",
}
var hostEpWithNameId = "named"

var hostEp2NoName = model.HostEndpoint{
	ProfileIDs: []string{"prof-2", "prof-3"},
	ExpectedIPv4Addrs: []net.IP{
		mustParseIP("10.0.0.2"),
		mustParseIP("10.0.0.3"),
	},
	ExpectedIPv6Addrs: []net.IP{
		mustParseIP("fc00:fe11::2"),
		mustParseIP("fc00:fe11::3"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	}),
}

var hostEp2NoNameKey = model.HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "unnamed",
}
var hostEpNoNameId = "unnamed"

// Canned tiers/policies.

var (
	order10 = float64(10)
	order20 = float64(20)
	order30 = float64(30)
)

// A variation of policy1_order20 but in tier-1 instead of default tier.
var policy1_tier1_order20 = model.Policy{
	Tier:     "tier-1",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20 = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_always = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types:            []string{"ingress", "egress"},
	PerformanceHints: []v3.PolicyPerformanceHint{v3.PerfHintAssumeNeededOnEveryNode},
}

var policy1_order20_ondemand = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types:            []string{"ingress", "egress"},
	PerformanceHints: []v3.PolicyPerformanceHint{v3.PerfHintAssumeNeededOnEveryNode},
}

var (
	protoTCP                                = numorstring.ProtocolFromStringV1("tcp")
	protoUDP                                = numorstring.ProtocolFromStringV1("udp")
	policy1_order20_with_named_port_tcpport = model.Policy{
		Tier:     "default",
		Order:    &order20,
		Selector: "a == 'a'",
		InboundRules: []model.Rule{
			{
				Protocol: &protoTCP,
				SrcPorts: []numorstring.Port{numorstring.NamedPort("tcpport")},
			},
		},
		OutboundRules: []model.Rule{
			{SrcSelector: bEpBSelector},
		},
		Types: []string{"ingress", "egress"},
	}
)

var policy1_order20_with_named_port_tcpport_negated = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol:    &protoTCP,
			NotSrcPorts: []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy_with_named_port_inherit = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol:    &protoTCP,
			SrcSelector: "profile == 'prof-1'",
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []model.Rule{},
	Types:         []string{"ingress", "egress"},
}

var policy1_order20_with_selector_and_named_port_tcpport = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol:    &protoTCP,
			SrcSelector: allSelector,
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_selector_and_negated_named_port_tcpport = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol:       &protoTCP,
			SrcSelector:    allSelector,
			NotSrcSelector: "foo == 'bar'",
			NotSrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	Types: []string{"ingress"},
}

var policy1_order20_with_selector_and_negated_named_port_tcpport_dest = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol:       &protoTCP,
			DstSelector:    allSelector,
			NotDstSelector: "foo == 'bar'",
			NotDstPorts:    []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	Types: []string{"ingress"},
}

var policy1_order20_with_selector_and_named_port_udpport = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol:    &protoUDP,
			SrcSelector: allSelector,
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("udpport")},
		},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_named_port_mismatched_protocol = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{
			Protocol: &protoTCP,
			SrcPorts: []numorstring.Port{numorstring.NamedPort("udpport")},
		},
	},
	OutboundRules: []model.Rule{
		{
			Protocol: &protoUDP,
			SrcPorts: []numorstring.Port{numorstring.NamedPort("tcpport")},
		},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_with_selector_and_named_port_tcpport2 = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []model.Rule{
		{
			Protocol:    &protoTCP,
			SrcSelector: allSelector,
			SrcPorts:    []numorstring.Port{numorstring.NamedPort("tcpport2")},
		},
	},
	Types: []string{"ingress", "egress"},
}

var policy1_order20_ingress_only = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	Types: []string{"ingress"},
}

var policy1_order20_egress_only = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	Types: []string{"egress"},
}

var policy1_order20_untracked = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	DoNotTrack: true,
}

var policy1_order20_pre_dnat = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	PreDNAT: true,
}

var policy1_order20_http_match = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{HTTPMatch: &httpMatchMethod},
	},
}

var policy1_order20_src_service_account = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []model.Rule{
		{OriginalSrcServiceAccountSelector: serviceAccountSelector},
	},
}

var policy1_order20_dst_service_account = model.Policy{
	Tier:     "default",
	Order:    &order20,
	Selector: "a == 'a'",
	OutboundRules: []model.Rule{
		{OriginalDstServiceAccountSelector: serviceAccountSelector},
	},
}

var profileRules1 = model.ProfileRules{
	InboundRules: []model.Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: "has(tag-1)"},
	},
}

var profileRulesWithTagInherit = model.ProfileRules{
	InboundRules: []model.Rule{
		{SrcSelector: tagSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: tagFoobarSelector},
	},
}

var profileRules1TagUpdate = model.ProfileRules{
	InboundRules: []model.Rule{
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []model.Rule{
		{SrcSelector: "has(tag-2)"},
	},
}

var profileRules1NegatedTagSelUpdate = model.ProfileRules{
	InboundRules: []model.Rule{
		{NotSrcSelector: bEpBSelector},
	},
	OutboundRules: []model.Rule{
		{NotSrcSelector: "has(tag-2)"},
	},
}

var profileLabels1Tag1 = &v3.Profile{
	ObjectMeta: metav1.ObjectMeta{
		Name: "prof-1",
	},
	Spec: v3.ProfileSpec{
		LabelsToApply: map[string]string{
			"profile": "prof-1",
			"tag-1":   "",
		},
	},
}

var profileLabels1 = &v3.Profile{
	ObjectMeta: metav1.ObjectMeta{
		Name: "prof-1",
	},
	Spec: v3.ProfileSpec{
		LabelsToApply: map[string]string{
			"profile": "prof-1",
		},
	},
}

var profileLabels2 = &v3.Profile{
	ObjectMeta: metav1.ObjectMeta{
		Name: "prof-2",
	},
	Spec: v3.ProfileSpec{
		LabelsToApply: map[string]string{
			"profile": "prof-2",
		},
	},
}

var profileLabelsTag1 = &v3.Profile{
	ObjectMeta: metav1.ObjectMeta{
		Name: "prof-1",
	},
	Spec: v3.ProfileSpec{
		LabelsToApply: map[string]string{
			"tag-1": "foobar",
		},
	},
}

var (
	tag1LabelID = ipSetIDForTag("tag-1")
	tag2LabelID = ipSetIDForTag("tag-2")
)

var (
	netSet1Key = model.NetworkSetKey{Name: "netset-1"}
	netSet1    = model.NetworkSet{
		Nets: []net.IPNet{
			mustParseNet("12.0.0.0/24"),
			mustParseNet("12.0.0.0/24"), // A dupe, why not!
			mustParseNet("12.1.0.0/24"),
			mustParseNet("10.0.0.1/32"), // Overlaps with host endpoint.
			mustParseNet("feed:beef::/32"),
			mustParseNet("feed:beef:0::/32"), // Non-canonical dupe.
		},
		Labels: uniquelabels.Make(map[string]string{
			"a": "b",
		}),
	}
)

var netSet1WithBEqB = model.NetworkSet{
	Nets: []net.IPNet{
		mustParseNet("12.0.0.0/24"),
		mustParseNet("12.0.0.0/24"), // A dupe, why not!
		mustParseNet("12.1.0.0/24"),
		mustParseNet("10.0.0.1/32"), // Overlaps with host endpoint.
	},
	Labels: uniquelabels.Make(map[string]string{
		"foo": "bar",
		"b":   "b",
	}),
}

var (
	netSet2Key = model.NetworkSetKey{Name: "netset-2"}
	netSet2    = model.NetworkSet{
		Nets: []net.IPNet{
			mustParseNet("12.0.0.0/24"), // Overlaps with netset-1
			mustParseNet("13.1.0.0/24"),
		},
		Labels: uniquelabels.Make(map[string]string{
			"a": "b",
		}),
	}
)

var (
	netSet3Key = model.NetworkSetKey{Name: "netset-3"}
	netSet3    = model.NetworkSet{
		Nets: []net.IPNet{
			mustParseNet("12.1.2.142/32"),
			mustParseNet("12.1.0.0/16"),
			mustParseNet("12.1.0.0/8"),
		},
		Labels: uniquelabels.Make(map[string]string{
			"a": "b",
		}),
	}
)

var (
	netset3Ip1a = mustParseNet("12.1.0.130/32").IP
	netset3Ip1b = mustParseNet("12.1.2.142/32").IP
)

var (
	localHostIP     = mustParseIP("192.168.0.1")
	remoteHostIP    = mustParseIP("192.168.0.2")
	remoteHostIPv6  = mustParseIP("dead:beef:0001::2")
	remoteHost2IP   = mustParseIP("192.168.0.3")
	remoteHost2IPv6 = mustParseIP("dead:beef:0001::3")
)

var (
	localHostIPWithPrefix  = "192.168.0.1/24"
	remoteHostIPWithPrefix = "192.168.0.2/24"
)

var localHostVXLANTunnelConfigKey = model.HostConfigKey{
	Hostname: localHostname,
	Name:     "IPv4VXLANTunnelAddr",
}

var remoteHostVXLANTunnelConfigKey = model.HostConfigKey{
	Hostname: remoteHostname,
	Name:     "IPv4VXLANTunnelAddr",
}

var remoteHostVXLANV6TunnelConfigKey = model.HostConfigKey{
	Hostname: remoteHostname,
	Name:     "IPv6VXLANTunnelAddr",
}

var remoteHost2VXLANTunnelConfigKey = model.HostConfigKey{
	Hostname: remoteHostname2,
	Name:     "IPv4VXLANTunnelAddr",
}

var remoteHostVXLANTunnelMACConfigKey = model.HostConfigKey{
	Hostname: remoteHostname,
	Name:     "VXLANTunnelMACAddr",
}

var remoteHostVXLANV6TunnelMACConfigKey = model.HostConfigKey{
	Hostname: remoteHostname,
	Name:     "VXLANTunnelMACAddrV6",
}

var ipPoolKey = model.IPPoolKey{
	CIDR: mustParseNet("10.0.0.0/16"),
}

var ipPoolKey2 = model.IPPoolKey{
	CIDR: mustParseNet("11.0.0.0/16"),
}

var hostCoveringIPPoolKey = model.IPPoolKey{
	CIDR: mustParseNet("192.168.0.0/24"),
}

var hostCoveringIPPool = model.IPPool{
	CIDR:       mustParseNet("192.168.0.0/24"),
	Disabled:   true,
	Masquerade: true,
}

var ipPoolWithIPIP = model.IPPool{
	CIDR:     mustParseNet("10.0.0.0/16"),
	IPIPMode: encap.Always,
}

var v6IPPoolKey = model.IPPoolKey{
	CIDR: mustParseNet("feed:beef::/64"),
}

var v6IPPool = model.IPPool{
	CIDR: mustParseNet("feed:beef::/64"),
}

var ipPoolWithVXLAN = model.IPPool{
	CIDR:       mustParseNet("10.0.0.0/16"),
	VXLANMode:  encap.Always,
	Masquerade: true,
}

var ipPool2WithVXLAN = model.IPPool{
	CIDR:       mustParseNet("11.0.0.0/16"),
	VXLANMode:  encap.Always,
	Masquerade: true,
}

var v6IPPoolWithVXLAN = model.IPPool{
	CIDR:       mustParseNet("feed:beef::/64"),
	VXLANMode:  encap.Always,
	Masquerade: true,
}

var workloadIPs = "WorkloadIPs"

var ipPoolWithVXLANSlash32 = model.IPPool{
	CIDR:       mustParseNet("10.0.0.0/32"),
	VXLANMode:  encap.Always,
	Masquerade: true,
}

var ipPoolWithVXLANCrossSubnet = model.IPPool{
	CIDR:       mustParseNet("10.0.0.0/16"),
	VXLANMode:  encap.CrossSubnet,
	Masquerade: false, // For coverage, make this different to the Always version of the pool
}

var remoteIPAMBlockKey = model.BlockKey{
	CIDR: mustParseNet("10.0.1.0/29"),
}

var remoteIPAMSlash32BlockKey = model.BlockKey{
	CIDR: mustParseNet("10.0.0.0/32"),
}

var remotev6IPAMBlockKey = model.BlockKey{
	CIDR: mustParseNet("feed:beef:0:0:1::/96"),
}

var localIPAMBlockKey = model.BlockKey{
	CIDR: mustParseNet("10.0.0.0/29"),
}

var (
	localHostAffinity   = "host:" + localHostname
	remoteHostAffinity  = "host:" + remoteHostname
	remoteHost2Affinity = "host:" + remoteHostname2
	remoteIPAMBlock     = model.AllocationBlock{
		CIDR:        mustParseNet("10.0.1.0/29"),
		Affinity:    &remoteHostAffinity,
		Allocations: make([]*int, 8),
		Unallocated: []int{0, 1, 2, 3, 4, 5, 6, 7},
	}
)

var remoteIPAMBlockSlash32 = model.AllocationBlock{
	CIDR:        mustParseNet("10.0.0.0/32"),
	Affinity:    &remoteHostAffinity,
	Allocations: make([]*int, 1),
	Unallocated: []int{0},
}

var remotev6IPAMBlock = model.AllocationBlock{
	CIDR:        mustParseNet("feed:beef:0:0:1::/96"),
	Affinity:    &remoteHostAffinity,
	Allocations: make([]*int, 8),
	Unallocated: []int{0, 1, 2, 3, 4, 5, 6, 7},
}

var remoteIPAMBlockWithBorrows = model.AllocationBlock{
	CIDR:     mustParseNet("10.0.1.0/29"),
	Affinity: &remoteHostAffinity,
	Allocations: []*int{
		intPtr(0),
		intPtr(1),
		intPtr(2),
		nil,
		nil,
		nil,
		nil,
		nil,
	},
	Unallocated: []int{3, 4, 5, 6, 7},
	Attributes: []model.AllocationAttribute{
		{},
		{ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: remoteHostname,
		}},
		{ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: remoteHostname2,
		}},
	},
}

var remoteIPAMBlockWithBorrowsSwitched = model.AllocationBlock{
	CIDR:     mustParseNet("10.0.1.0/29"),
	Affinity: &remoteHost2Affinity,
	Allocations: []*int{
		intPtr(0),
		intPtr(1),
		intPtr(2),
		nil,
		nil,
		nil,
		nil,
		nil,
	},
	Unallocated: []int{3, 4, 5, 6, 7},
	Attributes: []model.AllocationAttribute{
		{},
		{ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: remoteHostname2,
		}},
		{ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: remoteHostname,
		}},
	},
}

var localIPAMBlockWithBorrows = model.AllocationBlock{
	CIDR:     mustParseNet("10.0.0.0/29"),
	Affinity: &localHostAffinity,
	Allocations: []*int{
		intPtr(0),
		intPtr(1),
		intPtr(2),
		nil,
		nil,
		nil,
		nil,
		nil,
	},
	Unallocated: []int{3, 4, 5, 6, 7},
	Attributes: []model.AllocationAttribute{
		// 10.0.0.0
		{},

		// 10.0.0.1 - assigned locally.
		{ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: localHostname,
		}},

		// 10.0.0.2 - assigned to remoteHostname.
		{ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: remoteHostname,
		}},
	},
}

// Resource for endpoint slice and service policy tests.
var (
	p                 = int32(80)
	tcp               = v1.ProtocolTCP
	endpointSliceKey1 = model.ResourceKey{Name: "eps", Namespace: "default", Kind: "KubernetesEndpointSlice"}
	endpointSliceKey2 = model.ResourceKey{Name: "eps-2", Namespace: "default", Kind: "KubernetesEndpointSlice"}
	endpointSlice1    = discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "eps", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "svc"}},
		Endpoints: []discovery.Endpoint{
			{Addresses: []string{"10.0.0.1"}},
		},
		Ports: []discovery.EndpointPort{
			{Port: &p, Protocol: &tcp},
		},
	}
)

var endpointSlice1NewIPs = discovery.EndpointSlice{
	ObjectMeta: metav1.ObjectMeta{Name: "eps", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "svc"}},
	Endpoints: []discovery.Endpoint{
		{Addresses: []string{"10.0.0.1"}},
		{Addresses: []string{"10.0.0.2"}},
		{Addresses: []string{"10.0.0.3"}},
	},
	Ports: []discovery.EndpointPort{
		{Port: &p, Protocol: &tcp},
	},
}

var endpointSlice1NewIPs2 = discovery.EndpointSlice{
	ObjectMeta: metav1.ObjectMeta{Name: "eps", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "svc"}},
	Endpoints: []discovery.Endpoint{
		{Addresses: []string{"10.0.0.2"}},
		{Addresses: []string{"10.0.0.3"}},
		{Addresses: []string{"10.0.0.4"}},
	},
	Ports: []discovery.EndpointPort{
		{Port: &p, Protocol: &tcp},
	},
}

var endpointSlice2NewIPs2 = discovery.EndpointSlice{
	ObjectMeta: metav1.ObjectMeta{Name: "eps-2", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "svc"}},
	Endpoints: []discovery.Endpoint{
		{Addresses: []string{"10.0.0.2"}},
		{Addresses: []string{"10.0.0.3"}},
		{Addresses: []string{"10.0.0.4"}},
	},
	Ports: []discovery.EndpointPort{
		{Port: &p, Protocol: &tcp},
	},
}

var (
	servicePolicyKey  = model.PolicyKey{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy}
	servicePolicyKey2 = model.PolicyKey{Name: "svc-policy2", Kind: v3.KindGlobalNetworkPolicy}
	servicePolicy     = model.Policy{
		Tier:      "default",
		Namespace: "default",
		OutboundRules: []model.Rule{
			{
				Action:              "Allow",
				DstService:          "svc",
				DstServiceNamespace: "default",
			},
		},
		Types:    []string{"egress"},
		Selector: "all()",
	}

	servicePolicyNoPorts = model.Policy{
		Tier:      "default",
		Namespace: "default",
		InboundRules: []model.Rule{
			{
				Action:              "Allow",
				SrcService:          "svc",
				SrcServiceNamespace: "default",
				Protocol:            &protoTCP,
				SrcPorts: []numorstring.Port{
					{
						MinPort: 80,
						MaxPort: 80,
					},
				},
			},
		},
		Types:    []string{"ingress"},
		Selector: "all()",
	}
)

func intPtr(i int) *int {
	return &i
}

var (
	localHostVXLANTunnelIP     = "10.0.0.0"
	remoteHostVXLANTunnelIP    = "10.0.1.0"
	remoteHostVXLANV6TunnelIP  = "feed:beef:0:0:1::0"
	remoteHostVXLANTunnelIP2   = "10.0.1.1"
	remoteHost2VXLANTunnelIP   = "10.0.2.0"
	remoteHostVXLANTunnelMAC   = "66:74:c5:72:3f:01"
	remoteHostVXLANV6TunnelMAC = "10:f3:27:5c:47:66"
)

var t = true

var (
	wgPrivateKey1 = mustGeneratePrivateKey()
	wgPublicKey1  = wgPrivateKey1.PublicKey()
	wgPrivateKey2 = mustGeneratePrivateKey()
	wgPublicKey2  = wgPrivateKey2.PublicKey()
)

func mustGeneratePrivateKey() wgtypes.Key {
	if k, err := wgtypes.GeneratePrivateKey(); err != nil {
		log.WithError(err).Fatal("Error generating wireguard private key")
	} else {
		return k
	}
	// This will never run, but it's included to appease golanci-lint
	return wgtypes.Key{}
}
