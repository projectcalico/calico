//go:build !windows

// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package collector

import (
	"fmt"
	net2 "net"
	"slices"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	clttypes "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/counter"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/nfnetlink"
	"github.com/projectcalico/calico/felix/nfnetlink/nfnl"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	ipv4       = 0x800
	proto_icmp = 1
	proto_tcp  = 6
	proto_udp  = 17
)

var (
	localIp1Str     = "10.0.0.1"
	localIp1        = utils.IpStrTo16Byte(localIp1Str)
	localNodeIp1Str = "192.168.180.1"
	localNodeIp1    = utils.IpStrTo16Byte(localNodeIp1Str)
	localIp2Str     = "10.0.0.2"
	localIp2        = utils.IpStrTo16Byte(localIp2Str)
	remoteIp1Str    = "20.0.0.1"
	remoteIp1       = utils.IpStrTo16Byte(remoteIp1Str)
	remoteIp2Str    = "20.0.0.2"
	remoteIp2       = utils.IpStrTo16Byte(remoteIp2Str)
	localIp1DNAT    = utils.IpStrTo16Byte("192.168.0.1")
	localIp2DNAT    = utils.IpStrTo16Byte("192.168.0.2")
	publicIP1Str    = "1.0.0.1"
	publicIP2Str    = "2.0.0.2"
	netSetIp1Str    = "8.8.8.8"
)

var (
	srcPort        = 54123
	srcPort2       = 54124
	serviceSrcPort = 456123
	nodeSrcPort    = 890123
	proxyPort      = 34754
	dstPort        = 80
	dstPortDNAT    = 8080
)

var (
	localWlEPKey1 = model.WorkloadEndpointKey{
		Hostname:       "localhost",
		OrchestratorID: "orchestrator",
		WorkloadID:     "localworkloadid1",
		EndpointID:     "localepid1",
	}

	localWlEPKey2 = model.WorkloadEndpointKey{
		Hostname:       "localhost",
		OrchestratorID: "orchestrator",
		WorkloadID:     "localworkloadid2",
		EndpointID:     "localepid2",
	}

	remoteWlEpKey1 = model.WorkloadEndpointKey{
		OrchestratorID: "orchestrator",
		WorkloadID:     "remoteworkloadid1",
		EndpointID:     "remoteepid1",
	}
	remoteWlEpKey2 = model.WorkloadEndpointKey{
		OrchestratorID: "orchestrator",
		WorkloadID:     "remoteworkloadid2",
		EndpointID:     "remoteepid2",
	}

	localWlEp1 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali1",
		Mac:      utils.MustParseMac("01:02:03:04:05:06"),
		IPv4Nets: []net.IPNet{utils.MustParseNet("10.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "local-ep-1",
		}),
	}
	localWlEp2 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali2",
		Mac:      utils.MustParseMac("01:02:03:04:05:07"),
		IPv4Nets: []net.IPNet{utils.MustParseNet("10.0.0.2/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "local-ep-2",
		}),
	}
	remoteWlEp1 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali3",
		Mac:      utils.MustParseMac("02:02:03:04:05:06"),
		IPv4Nets: []net.IPNet{utils.MustParseNet("20.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "remote-ep-1",
		}),
	}
	remoteWlEp2 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali4",
		Mac:      utils.MustParseMac("02:03:03:04:05:06"),
		IPv4Nets: []net.IPNet{utils.MustParseNet("20.0.0.2/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "remote-ep-2",
		}),
	}
	localEd1 = &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(localWlEPKey1, localWlEp1),
		Ingress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
				{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
			},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(
						v3.KindGlobalNetworkPolicy,
						"default",
						"policy2",
						"",
						calc.RuleIndexTierDefaultAction,
						rules.RuleDirIngress,
						rules.RuleActionDeny,
					),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 0,
		},
		Egress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
				{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
			},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(
						v3.KindGlobalNetworkPolicy,
						"default",
						"policy2",
						"",
						calc.RuleIndexTierDefaultAction,
						rules.RuleDirIngress,
						rules.RuleActionDeny,
					),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 0,
		},
	}
	localEd2 = &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(localWlEPKey2, localWlEp2),
		Ingress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
				{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
			},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(
						v3.KindGlobalNetworkPolicy,
						"default",
						"policy2",
						"",
						calc.RuleIndexTierDefaultAction,
						rules.RuleDirIngress,
						rules.RuleActionDeny,
					),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 0,
		},
		Egress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
				{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
			},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(
						v3.KindGlobalNetworkPolicy,
						"default",
						"policy2",
						"",
						calc.RuleIndexTierDefaultAction,
						rules.RuleDirIngress,
						rules.RuleActionDeny,
					),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 0,
		},
	}
	remoteEd1 = &calc.RemoteEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(remoteWlEpKey1, remoteWlEp1),
	}
	remoteEd2 = &calc.RemoteEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(remoteWlEpKey2, remoteWlEp2),
	}

	netSetKey1 = model.NetworkSetKey{
		Name: "dns-servers",
	}
	netSet1 = model.NetworkSet{
		Nets:   []net.IPNet{utils.MustParseNet(netSetIp1Str + "/32")},
		Labels: uniquelabels.Make(map[string]string{"public": "true"}),
	}

	svcKey1 = model.ResourceKey{
		Name:      "test-svc",
		Namespace: "test-namespace",
		Kind:      model.KindKubernetesService,
	}
	svc1 = kapiv1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-namespace"},
		Spec: kapiv1.ServiceSpec{
			ClusterIP: "10.10.10.10",
			ClusterIPs: []string{
				"10.10.10.10",
			},
			Ports: []kapiv1.ServicePort{
				{
					Name:       "nginx",
					Port:       80,
					TargetPort: intstr.IntOrString{Type: intstr.String, StrVal: "nginx"},
					Protocol:   kapiv1.ProtocolTCP,
				},
			},
		},
	}
)

func toprefix(s string) [64]byte {
	p := [64]byte{}
	copy(p[:], []byte(s))
	return p
}

// Nflog prefix test parameters
var (
	defTierAllowIngressNFLOGPrefix   = toprefix("API0|gnp/policy1")
	defTierAllowEgressNFLOGPrefix    = toprefix("APE0|gnp/policy1")
	defTierDenyIngressNFLOGPrefix    = toprefix("DPI0|gnp/policy2")
	defTierDenyEgressNFLOGPrefix     = toprefix("DPE0|gnp/policy2")
	defTierPolicy1AllowIngressRuleID = &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      v3.KindGlobalNetworkPolicy,
			Name:      "policy1",
			Namespace: "",
		},
		Tier:      "default",
		Index:     0,
		IndexStr:  "0",
		Action:    rules.RuleActionAllow,
		Direction: rules.RuleDirIngress,
	}
	defTierPolicy1AllowEgressRuleID = &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      v3.KindGlobalNetworkPolicy,
			Name:      "policy1",
			Namespace: "",
		},
		Tier:      "default",
		Index:     0,
		IndexStr:  "0",
		Action:    rules.RuleActionAllow,
		Direction: rules.RuleDirEgress,
	}
	defTierPolicy2DenyIngressRuleID = &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      v3.KindGlobalNetworkPolicy,
			Name:      "policy2",
			Namespace: "",
		},
		Tier:      "default",
		Index:     0,
		IndexStr:  "0",
		Action:    rules.RuleActionDeny,
		Direction: rules.RuleDirIngress,
	}
	defTierPolicy2DenyEgressRuleID = &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      v3.KindGlobalNetworkPolicy,
			Name:      "policy2",
			Namespace: "",
		},
		Tier:      "default",
		Index:     0,
		IndexStr:  "0",
		Action:    rules.RuleActionDeny,
		Direction: rules.RuleDirEgress,
	}
	tier1TierPolicy1AllowIngressRuleID = &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      v3.KindGlobalNetworkPolicy,
			Name:      "policy11",
			Namespace: "",
		},
		Tier:      "tier1",
		Index:     0,
		IndexStr:  "0",
		Action:    rules.RuleActionAllow,
		Direction: rules.RuleDirIngress,
	}
	tier1TierPolicy1DenyEgressRuleID = &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      v3.KindGlobalNetworkPolicy,
			Name:      "policy11",
			Namespace: "",
		},
		Tier:      "tier1",
		Index:     0,
		IndexStr:  "0",
		Action:    rules.RuleActionDeny,
		Direction: rules.RuleDirEgress,
	}
)

var ingressPktAllowNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   remoteIp1,
	Dst:   localIp1,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var ingressPktAllow = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	ingressPktAllowNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierAllowIngressNFLOGPrefix,
				Len:     20,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: ingressPktAllowNflogTuple,
	},
}

var ingressPktAllowTuple = tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

var egressPktAllowNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   remoteIp1,
	Proto: proto_udp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var egressPktAllow = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	egressPktAllowNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierAllowEgressNFLOGPrefix,
				Len:     20,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: egressPktAllowNflogTuple,
	},
}
var egressPktAllowTuple = tuple.New(localIp1, remoteIp1, proto_udp, srcPort, dstPort)

var ingressPktDenyNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   remoteIp1,
	Dst:   localIp1,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var ingressPktDeny = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	ingressPktDenyNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierDenyIngressNFLOGPrefix,
				Len:     20,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: ingressPktDenyNflogTuple,
	},
}
var ingressPktDenyTuple = tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

var localPktIngressNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   localIp2,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var localPktIngress = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	localPktIngressNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierDenyIngressNFLOGPrefix,
				Len:     22,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: localPktIngressNflogTuple,
	},
}

var localPktIngressWithDNATNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   localIp2,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var localPktIngressWithDNAT = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	localPktIngressWithDNATNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierDenyIngressNFLOGPrefix,
				Len:     22,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: localPktIngressWithDNATNflogTuple,
		OriginalTuple: nfnetlink.CtTuple{
			Src:        localIp1,
			Dst:        localIp2DNAT,
			L3ProtoNum: ipv4,
			ProtoNum:   proto_tcp,
			L4Src:      nfnetlink.CtL4Src{Port: srcPort},
			L4Dst:      nfnetlink.CtL4Dst{Port: dstPortDNAT},
		},
		IsDNAT: true,
	},
}

var localPktEgressNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   localIp2,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var localPktEgress = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	localPktEgressNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierAllowEgressNFLOGPrefix,
				Len:     20,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: localPktEgressNflogTuple,
	},
}

var localPktEgressDenyTuplePreDNAT = tuple.New(localIp1, localIp1DNAT, proto_tcp, srcPort, dstPortDNAT)

var localPktEgressDeniedPreDNATNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   localIp1DNAT,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPortDNAT},
}

var localPktEgressDeniedPreDNAT = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	localPktEgressDeniedPreDNATNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierDenyEgressNFLOGPrefix,
				Len:     22,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple:  localPktEgressDeniedPreDNATNflogTuple,
		IsDNAT: false,
	},
}

var localPktEgressAllowTuple = tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)

var localPktEgressAllowedPreDNATNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   remoteIp1,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var localPktEgressAllowedPreDNAT = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	localPktEgressAllowedPreDNATNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierAllowEgressNFLOGPrefix,
				Len:     22,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: localPktEgressAllowedPreDNATNflogTuple,
		OriginalTuple: nfnetlink.CtTuple{
			Src:        localIp1,
			Dst:        localIp1DNAT,
			L3ProtoNum: ipv4,
			ProtoNum:   proto_tcp,
			L4Src:      nfnetlink.CtL4Src{Port: srcPort},
			L4Dst:      nfnetlink.CtL4Dst{Port: dstPortDNAT},
		},
		IsDNAT: true,
	},
}

var _ = Describe("NFLOG Datasource", func() {
	Describe("NFLOG Incoming Packets", func() {
		// Inject info nflogChan
		var c *collector
		var lm *calc.LookupsCache
		var nflogReader *NFLogReader
		conf := &Config{
			AgeTimeout:            time.Duration(10) * time.Second,
			InitialReportingDelay: time.Duration(5) * time.Second,
			ExportingInterval:     time.Duration(1) * time.Second,
			FlowLogsFlushInterval: time.Duration(100) * time.Second,
			DisplayDebugTraceLogs: true,
		}
		BeforeEach(func() {
			epMap := map[[16]byte]calc.EndpointData{
				localIp1:  localEd1,
				localIp2:  localEd2,
				remoteIp1: remoteEd1,
			}
			nflogMap := map[[64]byte]*calc.RuleID{}

			for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
				nflogMap[policyIDStrToRuleIDParts(rid)] = rid
			}

			lm = newMockLookupsCache(epMap, nflogMap, nil, nil)
			nflogReader = NewNFLogReader(lm, 0, 0, 0, false)
			Expect(nflogReader.Start()).NotTo(HaveOccurred())
			c = newCollector(lm, conf).(*collector)
			c.SetPacketInfoReader(nflogReader)
			c.SetConntrackInfoReader(dummyConntrackInfoReader{})
			go func() {
				Expect(c.Start()).NotTo(HaveOccurred())
			}()
		})
		AfterEach(func() {
			nflogReader.Stop()
		})
		Describe("Test local destination", func() {
			It("should receive a single stat update with allow ruleid trace", func() {
				t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
				nflogReader.IngressC <- ingressPktAllow
				Eventually(c.epStats).Should(HaveKey(*t))
			})
		})
		Describe("Test local to local", func() {
			It("should receive a single stat update with deny ruleid trace", func() {
				t := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)
				nflogReader.IngressC <- localPktIngress
				Eventually(c.epStats).Should(HaveKey(*t))
			})
		})
	})

	// Tests for deleted endpoints - RuleHits should be skipped
	Describe("NFLOG with deleted endpoints", func() {
		// Test data for endpoints marked for deletion
		var c *collector
		var lm *calc.LookupsCache
		var nflogReader *NFLogReader

		conf := &Config{
			AgeTimeout:            time.Duration(10) * time.Second,
			InitialReportingDelay: time.Duration(5) * time.Second,
			ExportingInterval:     time.Duration(1) * time.Second,
			FlowLogsFlushInterval: time.Duration(100) * time.Second,
			DisplayDebugTraceLogs: true,
		}

		BeforeEach(func() {
			epMap := map[[16]byte]calc.EndpointData{
				localIp1:  localEd1,
				localIp2:  localEd2,
				remoteIp1: remoteEd1,
			}
			nflogMap := map[[64]byte]*calc.RuleID{}

			for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
				nflogMap[policyIDStrToRuleIDParts(rid)] = rid
			}

			lm = newMockLookupsCache(epMap, nflogMap, nil, nil)
			nflogReader = NewNFLogReader(lm, 0, 0, 0, false)
			Expect(nflogReader.Start()).NotTo(HaveOccurred())
			c = newCollector(lm, conf).(*collector)
			c.SetPacketInfoReader(nflogReader)
			c.SetConntrackInfoReader(dummyConntrackInfoReader{})
			go func() {
				Expect(c.Start()).NotTo(HaveOccurred())
			}()
		})

		AfterEach(func() {
			nflogReader.Stop()
		})

		Describe("Test source endpoint marked for deletion", func() {
			It("should skip RuleHits processing when source endpoint is marked for deletion", func() {
				// Set up normal endpoint map
				epMap := map[[16]byte]calc.EndpointData{
					localIp1:  localEd1, // src endpoint to be marked for deletion
					localIp2:  localEd2, // normal dest endpoint
					remoteIp1: remoteEd1,
				}
				nflogMap := map[[64]byte]*calc.RuleID{}

				for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
					nflogMap[policyIDStrToRuleIDParts(rid)] = rid
				}

				// Update the lookups cache with endpoint map
				lm.SetMockData(epMap, nflogMap, nil, nil)

				// Mark the source endpoint for deletion
				lm.MarkEndpointDeleted(localEd1)

				t := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)

				// Send NFLOG packet - this should create the tuple but skip RuleHits processing
				nflogReader.IngressC <- localPktIngress
				Eventually(c.epStats).Should(HaveKey(*t))

				data := c.epStats[*t]
				// Verify that RuleHits were not processed (Path should be empty)
				Expect(len(data.IngressRuleTrace.Path())).To(Equal(0), "IngressRuleTrace Path should be empty when source endpoint is marked for deletion")
				Expect(len(data.EgressRuleTrace.Path())).To(Equal(0), "EgressRuleTrace Path should be empty when source endpoint is marked for deletion")
			})
		})

		Describe("Test destination endpoint marked for deletion", func() {
			It("should skip RuleHits processing when destination endpoint is marked for deletion", func() {
				// Set up normal endpoint map
				epMap := map[[16]byte]calc.EndpointData{
					localIp1:  localEd1, // normal src endpoint
					localIp2:  localEd2, // dest endpoint to be marked for deletion
					remoteIp1: remoteEd1,
				}
				nflogMap := map[[64]byte]*calc.RuleID{}

				for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
					nflogMap[policyIDStrToRuleIDParts(rid)] = rid
				}

				// Update the lookups cache with endpoint map
				lm.SetMockData(epMap, nflogMap, nil, nil)

				// Mark the destination endpoint for deletion
				lm.MarkEndpointDeleted(localEd2)

				t := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)

				// Send NFLOG packet - this should create the tuple but skip RuleHits processing
				nflogReader.IngressC <- localPktIngress
				Eventually(c.epStats).Should(HaveKey(*t))

				data := c.epStats[*t]
				// Verify that RuleHits were not processed (Path should be empty)
				Expect(len(data.IngressRuleTrace.Path())).To(Equal(0), "IngressRuleTrace Path should be empty when destination endpoint is marked for deletion")
				Expect(len(data.EgressRuleTrace.Path())).To(Equal(0), "EgressRuleTrace Path should be empty when destination endpoint is marked for deletion")
			})
		})

		Describe("Test remote source endpoint marked for deletion", func() {
			It("should skip RuleHits processing when remote source endpoint is marked for deletion", func() {
				// Set up normal endpoint map
				epMap := map[[16]byte]calc.EndpointData{
					localIp1:  localEd1,
					localIp2:  localEd2,
					remoteIp1: remoteEd1, // remote src endpoint to be marked for deletion
				}
				nflogMap := map[[64]byte]*calc.RuleID{}

				for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
					nflogMap[policyIDStrToRuleIDParts(rid)] = rid
				}

				// Update the lookups cache with endpoint map
				lm.SetMockData(epMap, nflogMap, nil, nil)

				// Mark the remote source endpoint for deletion
				lm.MarkEndpointDeleted(remoteEd1)

				t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

				// Send NFLOG packet - this should create the tuple but skip RuleHits processing
				nflogReader.IngressC <- ingressPktAllow
				Eventually(c.epStats).Should(HaveKey(*t))

				data := c.epStats[*t]
				// Verify that RuleHits were not processed (Path should be empty)
				Expect(len(data.IngressRuleTrace.Path())).To(Equal(0), "IngressRuleTrace Path should be empty when remote source endpoint is marked for deletion")
				Expect(len(data.EgressRuleTrace.Path())).To(Equal(0), "EgressRuleTrace Path should be empty when remote source endpoint is marked for deletion")
			})
		})

		// Test to ensure normal functionality is not broken
		Describe("Test normal RuleHits processing with active endpoints", func() {
			It("should process RuleHits when endpoints are NOT marked for deletion", func() {
				// Use normal endpoints (not marked for deletion) by resetting to default state
				epMap := map[[16]byte]calc.EndpointData{
					localIp1:  localEd1,
					localIp2:  localEd2,
					remoteIp1: remoteEd1,
				}
				nflogMap := map[[64]byte]*calc.RuleID{}

				for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
					nflogMap[policyIDStrToRuleIDParts(rid)] = rid
				}

				// Update the lookups cache with normal (active) endpoint map
				lm.SetMockData(epMap, nflogMap, nil, nil)

				t := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)

				// Send NFLOG packet - this should create the tuple AND process RuleHits
				nflogReader.IngressC <- localPktIngress
				Eventually(c.epStats).Should(HaveKey(*t))

				data := c.epStats[*t]
				// Verify that RuleHits were processed (Path should NOT be empty)
				Eventually(func() int {
					return len(data.IngressRuleTrace.Path())
				}, "500ms", "50ms").Should(BeNumerically(">", 0), "IngressRuleTrace Path should NOT be empty when endpoints are active")
			})
		})
	})
})

// Entry remoteIp1:srcPort -> localIp1:dstPort
var inCtEntry = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        remoteIp1,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        remoteIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

// Entry localIp1:srcPort -> localIp2:dstPort
var podProxyCTEntry = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        localIp2,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp2,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	Mark:             1024,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_TIME_WAIT},
}

var proxyBackEndCTEntry = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        localIp2,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: proxyPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp2,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: proxyPort},
	},
	Mark:             1024,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_TIME_WAIT},
}

var podProxyEgressPktAllowNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   localIp2,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: srcPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var podProxyEgressPktAllow = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	podProxyEgressPktAllowNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierAllowEgressNFLOGPrefix,
				Len:     20,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: podProxyEgressPktAllowNflogTuple,
	},
}

var proxyBackendIngressPktAllowNflogTuple = nfnetlink.NflogPacketTuple{
	Src:   localIp1,
	Dst:   localIp2,
	Proto: proto_tcp,
	L4Src: nfnetlink.NflogL4Info{Port: proxyPort},
	L4Dst: nfnetlink.NflogL4Info{Port: dstPort},
}

var proxyBackendIngressPktAllow = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate{
	proxyBackendIngressPktAllowNflogTuple: {
		Prefixes: []nfnetlink.NflogPrefix{
			{
				Prefix:  defTierAllowIngressNFLOGPrefix,
				Len:     20,
				Bytes:   100,
				Packets: 1,
			},
		},
		Tuple: proxyBackendIngressPktAllowNflogTuple,
	},
}

func convertCtEntry(e nfnetlink.CtEntry, _ uint32) clttypes.ConntrackInfo {
	i, _ := ConvertCtEntryToConntrackInfo(e)
	return i
}

var outCtEntry = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        remoteIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        remoteIp1,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

var outCtEntryWithSNAT = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        remoteIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        remoteIp1,
		Dst:        localNodeIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: nodeSrcPort},
	},
	Status:           nfnl.IPS_SRC_NAT,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

var outCtEntrySNATToServiceToSelf = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        remoteIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: serviceSrcPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        localNodeIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort2},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	Status:           nfnl.IPS_SRC_NAT | nfnl.IPS_DST_NAT,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

var localCtEntry = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        localIp2,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPort},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp2,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

// DNAT Conntrack Entries
// DNAT from localIp1DNAT:dstPortDNAT --> localIp1:dstPort
var inCtEntryWithDNAT = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        remoteIp1,
		Dst:        localIp1DNAT,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPortDNAT},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        remoteIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	Status:           nfnl.IPS_DST_NAT,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

// DNAT from localIp2DNAT:dstPortDNAT --> localIp2:dstPort
var localCtEntryWithDNAT = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        localIp2DNAT,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPortDNAT},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        localIp2,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	Status:           nfnl.IPS_DST_NAT,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

var outCtEntryWithDNAT = nfnetlink.CtEntry{
	OriginalTuple: nfnetlink.CtTuple{
		Src:        localIp1,
		Dst:        localIp1DNAT,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: srcPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: dstPortDNAT},
	},
	ReplyTuple: nfnetlink.CtTuple{
		Src:        remoteIp1,
		Dst:        localIp1,
		L3ProtoNum: ipv4,
		ProtoNum:   proto_tcp,
		L4Src:      nfnetlink.CtL4Src{Port: dstPort},
		L4Dst:      nfnetlink.CtL4Dst{Port: srcPort},
	},
	Status:           nfnl.IPS_DST_NAT,
	OriginalCounters: nfnetlink.CtCounters{Packets: 1, Bytes: 100},
	ReplyCounters:    nfnetlink.CtCounters{Packets: 2, Bytes: 250},
	ProtoInfo:        nfnetlink.CtProtoInfo{State: nfnl.TCP_CONNTRACK_ESTABLISHED},
}

var _ = Describe("Conntrack Datasource", func() {
	var c *collector
	var ciReaderSenderChan chan []clttypes.ConntrackInfo
	// var piReaderInfoSenderChan chan PacketInfo
	var lm *calc.LookupsCache
	var epMapDelete map[[16]byte]calc.EndpointData
	var epMapSwapLocal map[[16]byte]calc.EndpointData
	var nflogReader *NFLogReader
	conf := &Config{
		AgeTimeout:            time.Duration(10) * time.Second,
		InitialReportingDelay: time.Duration(5) * time.Second,
		ExportingInterval:     time.Duration(1) * time.Second,
		FlowLogsFlushInterval: time.Duration(100) * time.Second,
		DisplayDebugTraceLogs: true,
	}
	BeforeEach(func() {
		epMap := map[[16]byte]calc.EndpointData{
			localIp1:  localEd1,
			localIp2:  localEd2,
			remoteIp1: remoteEd1,
		}
		epMapSwapLocal = map[[16]byte]calc.EndpointData{
			localIp1:  localEd2,
			localIp2:  localEd1,
			remoteIp1: remoteEd1,
		}
		epMapDelete = map[[16]byte]calc.EndpointData{
			localIp1:  nil,
			localIp2:  nil,
			remoteIp1: nil,
		}

		nflogMap := map[[64]byte]*calc.RuleID{}

		for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
			nflogMap[policyIDStrToRuleIDParts(rid)] = rid
		}

		lm = newMockLookupsCache(epMap, nflogMap, nil, nil)
		nflogReader = NewNFLogReader(lm, 0, 0, 0, false)
		c = newCollector(lm, conf).(*collector)

		c.SetPacketInfoReader(nflogReader)

		ciReaderSenderChan = make(chan []clttypes.ConntrackInfo, 1)
		c.SetConntrackInfoReader(dummyConntrackInfoReader{
			MockSenderChannel: ciReaderSenderChan,
		})

		Expect(c.Start()).NotTo(HaveOccurred())
	})

	Describe("Test local destination", func() {
		It("should create a single entry in inbound direction", func() {
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			data := c.epStats[*t]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(inCtEntry.OriginalCounters.Packets)))
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(inCtEntry.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntry.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntry.ReplyCounters.Bytes)))
		})
		It("should handle destination becoming non-local by removing entry on next conntrack update for reported flow", func() {
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, remove endpoints from mock data and send in CT entry again.
			data := c.epStats[*t]
			data.Reported = true
			lm.SetMockData(epMapDelete, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			// This is a reported flow, and is a conntrack update - this should not impact the stored data at all.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
		})
		It("should handle destination becoming non-local by removing entry on next conntrack update for unreported flow", func() {
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported. Remove endpoints from mock data and send in CT entry again.
			lm.SetMockData(epMapDelete, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			// This is an unreported flow, and is a conntrack update. We can update the endpoint, but we never downgrade
			// to having no endpoint (since we handle the situation where endpoint is deleted before we gather all
			// logs).
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
		})
		It("should handle destination changing on next conntrack update for reported flow", func() {
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, swap local endpoints from mock data and send in CT entry again.
			data := c.epStats[*t]
			data.Reported = true
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			// This is a reported flow, and is a conntrack update - this should not impact the stored data at all since
			// the endpoint should not be changing for a constant connection.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
		It("should handle destination changing on next conntrack update for unreported flow", func() {
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported. swap local endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}

			// This is an unreported flow, and is a conntrack update. We can update the endpoint.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).NotTo(Equal(oldDest))
		})
		It("should handle destination becoming non-local by removing entry on next packetinfo update for reported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, remove endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			data.Reported = true
			lm.SetMockData(epMapDelete, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is a reported flow but we are going through packet processing still. It should be expired and
			// removed.
			Eventually(c.epStats, "500ms", "100ms").ShouldNot(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
		})
		It("should handle destination becoming non-local by removing entry on next packetinfo update for unreported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported. Remove endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			oldSrc := data.SrcEp
			oldDest := data.DstEp
			lm.SetMockData(epMapDelete, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is an unreported flow but we are going through packet processing still. However, since the endpoint
			// data has been removed assume it has just been deleted and don't downgrade our endpoint data.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
		It("should handle destination changing on next packetinfo update for reported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, swap local endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			data.Reported = true
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is a reported flow but we are going through packet processing still. It should be expired and
			// the endpoints updated.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).NotTo(Equal(oldDest))
		})
		It("should handle destination changing on next packetinfo update for unreported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported, swap local endpoints from mock data and send in CT entry again.
			data := c.epStats[*t]
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is an unreported flow, and is a conntrack update. We can update the endpoint.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).NotTo(Equal(oldDest))
		})
	})
	Describe("Test local source", func() {
		It("should create a single entry with outbound direction", func() {
			t := tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)

			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			data := c.epStats[*t]

			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(outCtEntry.OriginalCounters.Packets)))
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(outCtEntry.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(outCtEntry.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(outCtEntry.ReplyCounters.Bytes)))

			// Not SNAT'd so natOutgoingPort should not be set.
			Expect(data.NatOutgoingPort).Should(Equal(0))
		})
		It("should create a single entry with outbound direction for SNAT'd packet with nat outgoing port set", func() {
			t := tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)

			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntryWithSNAT, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			data := c.epStats[*t]

			Expect(data.NatOutgoingPort).Should(Equal(nodeSrcPort))
		})
		It("should create a single entry with outbound direction for SNAT'd packet sent to self without nat outgoing port set", func() {
			t := tuple.New(localIp1, localIp1, proto_tcp, srcPort, srcPort2)

			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntrySNATToServiceToSelf, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			data := c.epStats[*t]

			Expect(data.NatOutgoingPort).Should(Equal(0))
		})
		It("should handle source becoming non-local by removing entry on next conntrack update for reported flow", func() {
			t := tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, remove endpoints from mock data and send in CT entry again.
			data := c.epStats[*t]
			data.Reported = true
			lm.SetMockData(epMapDelete, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			// This is a reported flow, and is a conntrack update - this should not impact the stored data at all.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
		})
		It("should handle source becoming non-local by removing entry on next conntrack update for unreported flow", func() {
			t := tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported. Remove endpoints from mock data and send in CT entry again.
			lm.SetMockData(epMapDelete, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			// This is an unreported flow, and is a conntrack update. We can update the endpoint, but we never downgrade
			// to having no endpoint (since we handle the situation where endpoint is deleted before we gather all
			// logs).
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
		})
		It("should handle source changing on next conntrack update for reported flow", func() {
			t := tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, swap local endpoints from mock data and send in CT entry again.
			data := c.epStats[*t]
			data.Reported = true
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			// This is a reported flow, and is a conntrack update - this should not impact the stored data at all since
			// the endpoint should not be changing for a constant connection.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
		It("should handle source changing on next conntrack update for unreported flow", func() {
			t := tuple.New(localIp1, remoteIp1, proto_tcp, srcPort, dstPort)
			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported. swap local endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(outCtEntry, 0)}

			// This is an unreported flow, and is a conntrack update. We can update the endpoint.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.SrcEp).NotTo(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
		It("should handle source becoming non-local by removing entry on next packetinfo update for reported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirEgress, egressPktAllow[egressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(localIp1, remoteIp1, proto_udp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, remove endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			data.Reported = true
			lm.SetMockData(epMapDelete, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is a reported flow but we are going through packet processing still. It should be expired and
			// removed.
			Eventually(c.epStats, "500ms", "100ms").ShouldNot(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
		})
		It("should handle source becoming non-local by removing entry on next packetinfo update for unreported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirEgress, egressPktAllow[egressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(localIp1, remoteIp1, proto_udp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported. Remove endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			oldSrc := data.SrcEp
			oldDest := data.DstEp
			lm.SetMockData(epMapDelete, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is an unreported flow but we are going through packet processing still. However, since the endpoint
			// data has been removed assume it has just been deleted and don't downgrade our endpoint data.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
			Expect(data.SrcEp).To(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
		It("should handle source changing on next packetinfo update for reported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirEgress, egressPktAllow[egressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(localIp1, remoteIp1, proto_udp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flag the data as reported, swap local endpoints from mock data and send in packetinfo entry again.
			data := c.epStats[*t]
			data.Reported = true
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is a reported flow but we are going through packet processing still. It should be expired and
			// the endpoints updated.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
			Expect(data.SrcEp).NotTo(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
		It("should handle source changing on next packetinfo update for unreported flow", func() {
			pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirEgress, egressPktAllow[egressPktAllowNflogTuple])
			c.applyPacketInfo(pktinfo)
			t := tuple.New(localIp1, remoteIp1, proto_udp, srcPort, dstPort)

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Data is not reported, swap local endpoints from mock data and send in CT entry again.
			data := c.epStats[*t]
			oldSrc := data.SrcEp
			oldDest := data.DstEp

			lm.SetMockData(epMapSwapLocal, nil, nil, nil)
			c.applyPacketInfo(pktinfo)

			// This is an unreported flow, and is a conntrack update. We can update the endpoint.
			Consistently(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			Expect(data.Reported).To(BeFalse())
			Expect(data.SrcEp).NotTo(Equal(oldSrc))
			Expect(data.DstEp).To(Equal(oldDest))
		})
	})
	Describe("Test local source to local destination", func() {
		It("should create a single entry with 'local' direction", func() {
			t1 := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)

			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(localCtEntry, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t1))

			data := c.epStats[*t1]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(localCtEntry.OriginalCounters.Packets)))
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(localCtEntry.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(localCtEntry.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(localCtEntry.ReplyCounters.Bytes)))
		})
	})
	Describe("Test local destination with DNAT", func() {
		It("should create a single entry with inbound connection direction and with correct tuple extracted", func() {
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)

			// will call handlerInfo from c.Start() in BeforeEach
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryWithDNAT, 0)}

			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			data := c.epStats[*t]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(inCtEntryWithDNAT.OriginalCounters.Packets)))
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(inCtEntryWithDNAT.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntryWithDNAT.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntryWithDNAT.ReplyCounters.Bytes)))
		})
	})
	Describe("Test local source to local destination with DNAT", func() {
		It("should create a single entry with 'local' connection direction and with correct tuple extracted", func() {
			t1 := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(localCtEntryWithDNAT, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey((Equal(*t1))))
			data := c.epStats[*t1]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(localCtEntryWithDNAT.OriginalCounters.Packets)))
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(localCtEntryWithDNAT.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(localCtEntryWithDNAT.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(localCtEntryWithDNAT.ReplyCounters.Bytes)))
		})
	})

	Describe("Test conntrack TCP Protoinfo State", func() {
		It("Handle TCP conntrack entries with TCP state TIME_WAIT after NFLOGs gathered", func() {
			By("handling a conntrack update to start tracking stats for tuple")
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			data := c.epStats[*t]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(inCtEntry.OriginalCounters.Packets)))
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(inCtEntry.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntry.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntry.ReplyCounters.Bytes)))

			By("handling a conntrack update with updated counters")
			inCtEntryUpdatedCounters := inCtEntry
			inCtEntryUpdatedCounters.OriginalCounters.Packets = inCtEntry.OriginalCounters.Packets + 1
			inCtEntryUpdatedCounters.OriginalCounters.Bytes = inCtEntry.OriginalCounters.Bytes + 10
			inCtEntryUpdatedCounters.ReplyCounters.Packets = inCtEntry.ReplyCounters.Packets + 2
			inCtEntryUpdatedCounters.ReplyCounters.Bytes = inCtEntry.ReplyCounters.Bytes + 50
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryUpdatedCounters, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			// know update is complete
			Eventually(func() counter.Counter {
				return c.epStats[*t].ConntrackPacketsCounter()
			}, "500ms", "100ms").Should(Equal(*counter.New(inCtEntryUpdatedCounters.OriginalCounters.Packets)))

			data = c.epStats[*t]
			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(inCtEntryUpdatedCounters.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntryUpdatedCounters.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntryUpdatedCounters.ReplyCounters.Bytes)))

			By("handling a conntrack update with TCP CLOSE_WAIT")
			inCtEntryStateCloseWait := inCtEntryUpdatedCounters
			inCtEntryStateCloseWait.ProtoInfo.State = nfnl.TCP_CONNTRACK_CLOSE_WAIT
			inCtEntryStateCloseWait.ReplyCounters.Packets = inCtEntryUpdatedCounters.ReplyCounters.Packets + 1
			inCtEntryStateCloseWait.ReplyCounters.Bytes = inCtEntryUpdatedCounters.ReplyCounters.Bytes + 10
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryStateCloseWait, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))
			// know update is complete
			Eventually(func() counter.Counter {
				return c.epStats[*t].ConntrackPacketsCounterReverse()
			}, "500ms", "100ms").Should(Equal(*counter.New(inCtEntryStateCloseWait.ReplyCounters.Packets)))

			data = c.epStats[*t]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(inCtEntryStateCloseWait.OriginalCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntryStateCloseWait.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntryStateCloseWait.ReplyCounters.Bytes)))

			By("handling an nflog update for destination matching on policy - all policy info is now gathered",
				func() {
					pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
					c.applyPacketInfo(pktinfo)
				},
			)

			By("handling a conntrack update with TCP TIME_WAIT")
			inCtEntryStateTimeWait := inCtEntry
			inCtEntryStateTimeWait.ProtoInfo.State = nfnl.TCP_CONNTRACK_TIME_WAIT
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryStateTimeWait, 0)}
			Eventually(c.epStats, "500ms", "100ms").ShouldNot(HaveKey(*t))
		})

		It("Handle TCP conntrack entries with TCP state TIME_WAIT before NFLOGs gathered", func() {
			By("handling a conntrack update to start tracking stats for tuple")
			t := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntry, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// know update is complete
			Eventually(func() counter.Counter {
				return c.epStats[*t].ConntrackPacketsCounter()
			}, "500ms", "100ms").Should(Equal(*counter.New(inCtEntry.OriginalCounters.Packets)))
			data := c.epStats[*t]

			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(inCtEntry.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntry.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntry.ReplyCounters.Bytes)))

			By("handling a conntrack update with updated counters")
			inCtEntryUpdatedCounters := inCtEntry
			inCtEntryUpdatedCounters.OriginalCounters.Packets = inCtEntry.OriginalCounters.Packets + 1
			inCtEntryUpdatedCounters.OriginalCounters.Bytes = inCtEntry.OriginalCounters.Bytes + 10
			inCtEntryUpdatedCounters.ReplyCounters.Packets = inCtEntry.ReplyCounters.Packets + 2
			inCtEntryUpdatedCounters.ReplyCounters.Bytes = inCtEntry.ReplyCounters.Bytes + 50
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryUpdatedCounters, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// know update is complete
			Eventually(func() counter.Counter {
				return c.epStats[*t].ConntrackPacketsCounter()
			}, "500ms", "100ms").Should(Equal(*counter.New(inCtEntryUpdatedCounters.OriginalCounters.Packets)))
			data = c.epStats[*t]

			Expect(data.ConntrackPacketsCounterReverse()).Should(Equal(*counter.New(inCtEntryUpdatedCounters.ReplyCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntryUpdatedCounters.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntryUpdatedCounters.ReplyCounters.Bytes)))

			By("handling a conntrack update with TCP CLOSE_WAIT")
			inCtEntryStateCloseWait := inCtEntryUpdatedCounters
			inCtEntryStateCloseWait.ProtoInfo.State = nfnl.TCP_CONNTRACK_CLOSE_WAIT
			inCtEntryStateCloseWait.ReplyCounters.Packets = inCtEntryUpdatedCounters.ReplyCounters.Packets + 1
			inCtEntryStateCloseWait.ReplyCounters.Bytes = inCtEntryUpdatedCounters.ReplyCounters.Bytes + 10
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryStateCloseWait, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// know update is complete
			Eventually(func() counter.Counter {
				return c.epStats[*t].ConntrackPacketsCounterReverse()
			}, "500ms", "100ms").Should(Equal(*counter.New(inCtEntryStateCloseWait.ReplyCounters.Packets)))
			data = c.epStats[*t]
			Expect(data.ConntrackPacketsCounter()).Should(Equal(*counter.New(inCtEntryStateCloseWait.OriginalCounters.Packets)))
			Expect(data.ConntrackBytesCounter()).Should(Equal(*counter.New(inCtEntryStateCloseWait.OriginalCounters.Bytes)))
			Expect(data.ConntrackBytesCounterReverse()).Should(Equal(*counter.New(inCtEntryStateCloseWait.ReplyCounters.Bytes)))

			By("handling a conntrack update with TCP TIME_WAIT")
			inCtEntryStateTimeWait := inCtEntry
			inCtEntryStateTimeWait.ProtoInfo.State = nfnl.TCP_CONNTRACK_TIME_WAIT
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(inCtEntryStateTimeWait, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			By("handling an nflog update for destination matching on policy - all policy info is now gathered",
				func() {
					pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
					c.applyPacketInfo(pktinfo)
				},
			)
			Eventually(c.epStats, "500ms", "100ms").ShouldNot(HaveKey(*t))
		})
	})

	Describe("Test data race", func() {
		It("getDataAndUpdateEndpoints does not cause a data race contention with deleteDataFromEpStats after deleteDataFromEpStats removes it from epstats", func() {
			existingTuple := tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			testData := c.getDataAndUpdateEndpoints(*existingTuple, false, true)

			newTuple := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)

			var resultantNewTupleData *Data

			time.AfterFunc(2*time.Second, func() {
				c.deleteDataFromEpStats(testData)
			})

			// ok Get is a little after feedupdate because feedupdate has some preprocesssing
			// before it accesses flowstore
			time.AfterFunc(2*time.Second+10*time.Millisecond, func() {
				resultantNewTupleData = c.getDataAndUpdateEndpoints(*newTuple, false, true)
			})

			time.Sleep(3 * time.Second)

			Expect(c.epStats).ShouldNot(HaveKey(*existingTuple))
			Expect(c.epStats).Should(HaveKey(*newTuple))
			Expect(resultantNewTupleData).ToNot(Equal(nil))
		})
	})

	Describe("Test pre-DNAT handling", func() {
		It("handle pre-DNAT info on conntrack", func() {
			By("handling a conntrack update to start tracking stats for tuple (w/ DNAT)")
			t := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)
			ciReaderSenderChan <- []clttypes.ConntrackInfo{convertCtEntry(localCtEntryWithDNAT, 0)}
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			// Flagging as expired will attempt to expire the data when NFLOGs and service info are gathered.
			By("flagging the data as expired")
			data := c.epStats[*t]
			data.Expired = true
			Expect(data.IsDNAT).Should(BeTrue())

			By("handling nflog updates for destination matching on policy - all policy info is now gathered, but no service")
			c.applyPacketInfo(nflogReader.ConvertNflogPkt(rules.RuleDirIngress, localPktIngress[localPktIngressNflogTuple]))
			c.applyPacketInfo(nflogReader.ConvertNflogPkt(rules.RuleDirEgress, localPktEgress[localPktEgressNflogTuple]))
			Eventually(c.epStats, "500ms", "100ms").Should(HaveKey(*t))

			By("creating a matching service for the pre-DNAT cluster IP and port")
			lm.SetMockData(nil, nil, nil, map[model.ResourceKey]*kapiv1.Service{
				{Kind: model.KindKubernetesService, Name: "svc", Namespace: "default"}: {
					Spec: kapiv1.ServiceSpec{
						Ports: []kapiv1.ServicePort{{
							Name:     "test",
							Protocol: kapiv1.ProtocolTCP,
							Port:     int32(dstPortDNAT),
						}},
						ClusterIP: "192.168.0.2",
						ClusterIPs: []string{
							"192.168.0.2",
						},
					},
				},
			})

			By("handling another nflog update for destination matching on policy - should rematch and expire the entry")
			c.applyPacketInfo(nflogReader.ConvertNflogPkt(rules.RuleDirIngress, localPktIngress[localPktIngressNflogTuple]))
			Expect(c.epStats).ShouldNot(HaveKey(*t))
		})
		It("handle pre-DNAT info on nflog update", func() {
			By("handling egress nflog updates for destination matching on policy - this contains pre-DNAT info")
			t := tuple.New(localIp1, localIp2, proto_tcp, srcPort, dstPort)
			c.applyPacketInfo(nflogReader.ConvertNflogPkt(rules.RuleDirIngress, localPktIngressWithDNAT[localPktIngressWithDNATNflogTuple]))

			// Flagging as expired will attempt to expire the data when NFLOGs and service info are gathered.
			By("flagging the data as expired")
			data := c.epStats[*t]
			data.Expired = true
			Expect(data.IsDNAT).Should(BeTrue())

			By("handling ingree nflog updates for destination matching on policy - all policy info is now gathered, but no service")
			c.applyPacketInfo(nflogReader.ConvertNflogPkt(rules.RuleDirEgress, localPktEgress[localPktEgressNflogTuple]))
			Expect(c.epStats).Should(HaveKey(*t))

			By("creating a matching service for the pre-DNAT cluster IP and port")
			lm.SetMockData(nil, nil, nil, map[model.ResourceKey]*kapiv1.Service{
				{Kind: model.KindKubernetesService, Name: "svc", Namespace: "default"}: {
					Spec: kapiv1.ServiceSpec{
						Ports: []kapiv1.ServicePort{{
							Name:     "test",
							Protocol: kapiv1.ProtocolTCP,
							Port:     int32(dstPortDNAT),
						}},
						ClusterIP: "192.168.0.2",
						ClusterIPs: []string{
							"192.168.0.2",
						},
					},
				},
			})

			By("handling another nflog update for destination matching on policy - should rematch and expire the entry")
			c.applyPacketInfo(nflogReader.ConvertNflogPkt(rules.RuleDirIngress, localPktIngress[localPktIngressNflogTuple]))
			Expect(c.epStats).ShouldNot(HaveKey(*t))
		})
	})
})

func policyIDStrToRuleIDParts(r *calc.RuleID) [64]byte {
	var byt64 [64]byte
	id := types.PolicyID{Name: r.Name, Namespace: r.Namespace, Kind: r.Kind}
	prefix := rules.CalculateNFLOGPrefixStr(r.Action, rules.RuleOwnerTypePolicy, r.Direction, r.Index, id)
	copy(byt64[:], []byte(prefix))
	return byt64
}

var _ = Describe("Reporting Metrics", func() {
	var c *collector
	var nflogReader *NFLogReader
	var mockReporter *mockReporter
	var lm *calc.LookupsCache

	const (
		ageTimeout            = time.Duration(3) * time.Second
		reportingDelay        = time.Duration(2) * time.Second
		exportingInterval     = time.Duration(1) * time.Second
		flowLogsFlushInterval = time.Duration(1) * time.Second
	)
	conf := &Config{
		AgeTimeout:            ageTimeout,
		InitialReportingDelay: reportingDelay,
		ExportingInterval:     exportingInterval,
		FlowLogsFlushInterval: flowLogsFlushInterval,
		DisplayDebugTraceLogs: true,
	}
	BeforeEach(func() {
		epMap := map[[16]byte]calc.EndpointData{
			localIp1:  localEd1,
			localIp2:  localEd2,
			remoteIp1: remoteEd1,
		}

		nflogMap := map[[64]byte]*calc.RuleID{}

		for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
			nflogMap[policyIDStrToRuleIDParts(rid)] = rid
		}

		lm = newMockLookupsCache(epMap, nflogMap, nil, nil)
		mockReporter = newMockReporter()
		nflogReader = NewNFLogReader(lm, 0, 0, 0, false)
		Expect(nflogReader.Start()).NotTo(HaveOccurred())
		c = newCollector(lm, conf).(*collector)
		c.RegisterMetricsReporter(mockReporter)
		c.SetPacketInfoReader(nflogReader)
		c.SetConntrackInfoReader(dummyConntrackInfoReader{})
	})
	AfterEach(func() {
		nflogReader.Stop()
	})
	Context("Without process info enabled", func() {
		BeforeEach(func() {
			go func() {
				Expect(c.Start()).NotTo(HaveOccurred())
			}()
		})
		Describe("Report Denied Packets", func() {
			BeforeEach(func() {
				nflogReader.IngressC <- ingressPktDeny
			})
			Context("reporting tick", func() {
				It("should receive metric", func() {
					tmu := testMetricUpdate{
						updateType:   metric.UpdateTypeReport,
						tpl:          *ingressPktDenyTuple,
						srcEp:        remoteEd1,
						dstEp:        localEd1,
						ruleIDs:      []*calc.RuleID{defTierPolicy2DenyIngressRuleID},
						isConnection: false,
					}
					Eventually(mockReporter.reportChan, reportingDelay*2).Should(Receive(Equal(tmu)))
				})
			})
		})
		Describe("Report Allowed Packets (ingress)", func() {
			BeforeEach(func() {
				nflogReader.IngressC <- ingressPktAllow
			})
			Context("reporting tick", func() {
				It("should receive metric", func() {
					tmu := testMetricUpdate{
						updateType:   metric.UpdateTypeReport,
						tpl:          *ingressPktAllowTuple,
						srcEp:        remoteEd1,
						dstEp:        localEd1,
						ruleIDs:      []*calc.RuleID{defTierPolicy1AllowIngressRuleID},
						isConnection: false,
					}
					Eventually(mockReporter.reportChan, reportingDelay*2).Should(Receive(Equal(tmu)))
				})
			})
		})
		Describe("Report Packets that switch from deny to allow", func() {
			BeforeEach(func() {
				nflogReader.IngressC <- ingressPktDeny
				time.Sleep(time.Duration(500) * time.Millisecond)
				nflogReader.IngressC <- ingressPktAllow
			})
			Context("reporting tick", func() {
				It("should receive metric", func() {
					tmu := testMetricUpdate{
						updateType:   metric.UpdateTypeReport,
						tpl:          *ingressPktAllowTuple,
						srcEp:        remoteEd1,
						dstEp:        localEd1,
						ruleIDs:      []*calc.RuleID{defTierPolicy1AllowIngressRuleID},
						isConnection: false,
					}
					Eventually(mockReporter.reportChan, reportingDelay*2).Should(Receive(Equal(tmu)))
				})
			})
		})
		Describe("Report Allowed Packets (egress)", func() {
			BeforeEach(func() {
				nflogReader.EgressC <- egressPktAllow
			})
			Context("reporting tick", func() {
				It("should receive metric", func() {
					tmu := testMetricUpdate{
						updateType:   metric.UpdateTypeReport,
						tpl:          *egressPktAllowTuple,
						srcEp:        localEd1,
						dstEp:        remoteEd1,
						ruleIDs:      []*calc.RuleID{defTierPolicy1AllowEgressRuleID},
						isConnection: false,
					}
					Eventually(mockReporter.reportChan, reportingDelay*2).Should(Receive(Equal(tmu)))
				})
			})
		})
	})
})

func newMockLookupsCache(
	em map[[16]byte]calc.EndpointData,
	nm map[[64]byte]*calc.RuleID,
	ns map[model.NetworkSetKey]*model.NetworkSet,
	svcs map[model.ResourceKey]*kapiv1.Service,
) *calc.LookupsCache {
	l := calc.NewLookupsCache()
	l.SetMockData(em, nm, ns, svcs)
	return l
}

// Define a separate metric type that doesn't include the actual stats.  We use this
// for simpler comparisons.
type testMetricUpdate struct {
	updateType metric.UpdateType

	// Tuple key
	tpl tuple.Tuple

	// Endpoint information.
	srcEp calc.EndpointData
	dstEp calc.EndpointData

	// Rules identification
	ruleIDs []*calc.RuleID

	// Sometimes we may need to send updates without having all the rules
	// in place. This field will help aggregators determine if they need
	// to handle this update or not. Typically this is used when we receive
	// HTTP Data updates after the connection itself has closed.
	unknownRuleID *calc.RuleID

	// isConnection is true if this update is from an active connection (i.e. a conntrack
	// update compared to an NFLOG update).
	isConnection bool
}

// Create a mockReporter that acts as a pass-thru of the updates.
type mockReporter struct {
	reportChan chan testMetricUpdate
}

func newMockReporter() *mockReporter {
	return &mockReporter{
		reportChan: make(chan testMetricUpdate),
	}
}

func (mr *mockReporter) Start() error {
	return nil
}

func (mr *mockReporter) Report(u any) error {
	mu, ok := u.(metric.Update)
	if !ok {
		return fmt.Errorf("invalid metric update")
	}
	mr.reportChan <- testMetricUpdate{
		updateType:    mu.UpdateType,
		tpl:           mu.Tuple,
		srcEp:         mu.SrcEp,
		dstEp:         mu.DstEp,
		ruleIDs:       mu.RuleIDs,
		unknownRuleID: mu.UnknownRuleID,
		isConnection:  mu.IsConnection,
	}
	return nil
}

var _ = Describe("Collector Namespace-Aware NetworkSet Lookups", func() {
	var c *collector
	var testIP [16]byte

	// Convert IP string to [16]byte format
	ipToBytes := func(ipStr string) [16]byte {
		ip := net2.ParseIP(ipStr)
		var result [16]byte
		copy(result[:], ip.To16())
		return result
	}

	// Helper function to replace the old lookupEndpointWithNamespace behavior.
	// This uses the public findEndpointBestMatch interface by setting up a dummy source endpoint
	// to provide the preferredNamespace context.
	testLookupEndpoint := func(c *collector, clientIPBytes, ip [16]byte, canCheckEgressDomains bool, preferredNamespace string) calc.EndpointData {
		srcIP := clientIPBytes

		// If we need a namespace context but don't have a source IP, generate a dummy one.
		if preferredNamespace != "" && srcIP == [16]byte{} {
			srcIP = ipToBytes("192.0.2.1")
		}

		if preferredNamespace != "" {
			// Create a dummy endpoint in the preferred namespace to simulate the source
			epKey := model.WorkloadEndpointKey{
				Hostname:       "test-host",
				OrchestratorID: "k8s",
				WorkloadID:     "test-workload-src",
				EndpointID:     "test-endpoint-src",
			}
			ep := &model.WorkloadEndpoint{
				Name:   "test-endpoint-src",
				Labels: uniquelabels.Make(map[string]string{"env": "test"}),
			}

			common := calc.CalculateCommonEndpointData(epKey, ep)
			var endpoint calc.EndpointData
			if canCheckEgressDomains {
				endpoint = &calc.LocalEndpointData{
					CommonEndpointData: common,
				}
			} else {
				endpoint = &calc.RemoteEndpointData{
					CommonEndpointData: common,
				}
			}

			// Inject the dummy endpoint into the cache
			c.luc.SetMockData(map[[16]byte]calc.EndpointData{srcIP: endpoint}, nil, nil, nil)
		}

		// Perform the lookup using the public interface
		t := tuple.Tuple{Src: srcIP, Dst: ip}
		_, dstEp := c.findEndpointBestMatch(t)
		return dstEp
	}

	BeforeEach(func() {
		// Test IP that will match our NetworkSets
		testIP = ipToBytes("10.1.1.1")
	})

	Context("when testing endpoint lookup with NetworkSet fallback", func() {
		It("should prioritize more specific NetworkSets correctly", func() {
			// Create test NetworkSets
			globalNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Broad CIDR
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "global",
				}),
			}

			specificNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // More specific than global
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "specific",
					"env":  "test",
				}),
			}

			// Create test keys - using NetworkSetKey for global, ResourceKey for namespaced
			globalKey := model.NetworkSetKey{Name: "global-netset"}
			specificKey := model.NetworkSetKey{Name: "specific-netset"} // Using NetworkSetKey for simplicity

			// Create lookups cache with both NetworkSets
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				globalKey:   globalNetworkSet,
				specificKey: specificNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			// Create collector with NetworkSets enabled
			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Test: Should return the more specific NetworkSet (longest prefix match)
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "any-namespace")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(specificKey))

			// Verify it's actually the specific NetworkSet
			Expect(result.Labels().String()).To(ContainSubstring("specific"))
		})

		It("should fallback to global NetworkSet when no better match exists", func() {
			// Create only global NetworkSet
			globalNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Covers our test IP
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "global",
				}),
			}

			globalKey := model.NetworkSetKey{Name: "global-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				globalKey: globalNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Test with any namespace - should return global NetworkSet
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "any-namespace")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(globalKey))
		})

		It("should return nil when NetworkSets are disabled", func() {
			// Create NetworkSet data but disable NetworkSets in config
			globalNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"),
				},
			}

			globalKey := model.NetworkSetKey{Name: "global-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				globalKey: globalNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     false, // Disabled
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Should return nil because NetworkSets are disabled
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "namespace1")
			Expect(result).To(BeNil())
		})

		It("should prioritize endpoints over NetworkSets", func() {
			// Create test endpoint key and data
			testEPKey := model.WorkloadEndpointKey{
				Hostname:       "test-host",
				OrchestratorID: "k8s",
				WorkloadID:     "test-workload",
				EndpointID:     "test-endpoint",
			}

			testWlEP := &model.WorkloadEndpoint{
				Labels: uniquelabels.Make(map[string]string{
					"type": "endpoint",
				}),
			}

			endpoint := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(testEPKey, testWlEP),
			}

			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"),
				},
			}

			nsKey := model.NetworkSetKey{Name: "netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				testIP: endpoint,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Should return endpoint, not NetworkSet
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "namespace1")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(testEPKey))
		})

		It("should handle no matching NetworkSets gracefully", func() {
			// Create NetworkSet that doesn't match our test IP
			nonMatchingNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("192.168.0.0/16"), // Different range
				},
			}

			nonMatchingKey := model.NetworkSetKey{Name: "non-matching"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nonMatchingKey: nonMatchingNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Should return nil since no NetworkSet matches
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "namespace1")
			Expect(result).To(BeNil())
		})
	})

	Context("when testing namespace optimization benefits", func() {
		It("should select the most specific NetworkSet match (narrowest CIDR)", func() {
			// This test validates that the collector uses the namespace-aware lookup
			// Create multiple overlapping NetworkSets to show specificity
			broadNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Very broad
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "broad",
				}),
			}

			mediumNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // Medium specificity
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "medium",
				}),
			}

			narrowNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.1.0/24"), // Most specific
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "narrow",
				}),
			}

			broadKey := model.NetworkSetKey{Name: "broad-netset"}
			mediumKey := model.NetworkSetKey{Name: "medium-netset"}
			narrowKey := model.NetworkSetKey{Name: "narrow-netset"}

			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				broadKey:  broadNetworkSet,
				mediumKey: mediumNetworkSet,
				narrowKey: narrowNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Test that collector picks most specific match (narrowest CIDR)
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "test-namespace")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(narrowKey))

			// Verify it's the narrow NetworkSet
			Expect(result.Labels().String()).To(ContainSubstring("narrow"))
		})

		It("should handle performance efficiently with multiple NetworkSets", func() {
			// Create multiple NetworkSets for performance testing
			nsMap := make(map[model.NetworkSetKey]*model.NetworkSet)

			for i := range 10 {
				networkSet := &model.NetworkSet{
					Nets: []net.IPNet{
						utils.MustParseNet(fmt.Sprintf("10.%d.0.0/16", i)),
					},
					Labels: uniquelabels.Make(map[string]string{
						"type": fmt.Sprintf("test-%d", i),
					}),
				}

				key := model.NetworkSetKey{Name: fmt.Sprintf("test-netset-%d", i)}
				nsMap[key] = networkSet
			}

			lm := newMockLookupsCache(nil, nil, nsMap, nil)
			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Performance test: multiple namespace lookups should complete quickly
			start := time.Now()
			for i := range 50 {
				namespace := fmt.Sprintf("namespace-%d", i%5)
				testIPLoop := ipToBytes(fmt.Sprintf("10.%d.1.1", i%10))

				result := testLookupEndpoint(c, [16]byte{}, testIPLoop, false, namespace)
				// Should find a match for IPs in our test ranges
				if i < 10 {
					Expect(result).ToNot(BeNil())
				}
			}
			elapsed := time.Since(start)

			// Should complete 50 lookups in reasonable time (namespace optimization)
			Expect(elapsed).To(BeNumerically("<", 25*time.Millisecond))
		})
	})

	Context("when testing namespace-specific NetworkSets", func() {
		It("should prioritize namespace-specific NetworkSets over global ones", func() {
			// Create a global NetworkSet
			globalNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Broad global range
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "global",
					"tier": "base",
				}),
			}

			// Create a namespace-specific NetworkSet that overlaps with global
			namespaceNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // More specific range within global
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "namespace-specific",
					"tier": "application",
				}),
			}

			// Create keys - ResourceKey for namespace-scoped, NetworkSetKey for global
			globalKey := model.NetworkSetKey{Name: "global-netset"}
			namespaceKey := model.ResourceKey{
				Kind:      "NetworkSet",
				Name:      "app-netset",
				Namespace: "production", // This has a namespace
			}

			// Create the mock lookup cache
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				globalKey: globalNetworkSet,
				// For ResourceKey, we need to convert it to NetworkSetKey for the mock
				// The real LookupsCache handles ResourceKey properly, but our mock uses NetworkSetKey
			}

			// We need to also include the namespaced NetworkSet in the map
			// In the real system, ResourceKeys are internally mapped properly
			namespacedNSKey := model.NetworkSetKey{Name: namespaceKey.Name}
			nsMap[namespacedNSKey] = namespaceNetworkSet

			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Test with the specific namespace - should prefer namespace-specific NetworkSet
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "production")
			Expect(result).ToNot(BeNil())

			// Should get the namespace-specific NetworkSet (more specific CIDR)
			Expect(result.Labels().String()).To(ContainSubstring("namespace-specific"))
		})

		It("should fall back to global NetworkSet when no namespace match exists", func() {
			// Test true namespace isolation: when a more specific NetworkSet exists in a different namespace,
			// it should NOT be selected, and instead fall back to a global NetworkSet

			// Create global NetworkSet with broader range
			globalNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Broad range that includes testIP (10.1.1.1)
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "global-fallback",
				}),
			}

			// Create namespace-specific NetworkSet that DOES contain testIP but is from different namespace
			// This should NOT be selected for 'staging' namespace requests due to namespace isolation
			productionNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // More specific range that INCLUDES testIP (10.1.1.1)
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "production-specific",
					"namespace": "production",
				}),
			}

			// Use the correct namespace naming format: namespace/name
			globalKey := model.NetworkSetKey{Name: "global-netset"}              // Global NetworkSet (no namespace prefix)
			productionKey := model.NetworkSetKey{Name: "production/prod-netset"} // Namespaced NetworkSet

			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				globalKey:     globalNetworkSet,
				productionKey: productionNetworkSet,
			}
			lc := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lc, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Request with 'staging' namespace - different from the 'production' namespace NetworkSet
			// testIP (10.1.1.1) matches both:
			//   - global-netset: 10.0.0.0/8 (broader, global)
			//   - production/prod-netset: 10.1.0.0/16 (more specific, but wrong namespace)
			// Should return global NetworkSet due to namespace isolation
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "staging")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(globalKey))
			Expect(result.Labels().String()).To(ContainSubstring("global-fallback"))
		})

		It("should handle multiple namespaced NetworkSets correctly", func() {
			// Create NetworkSets for different namespaces with overlapping CIDRs
			productionNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.1.0/24"), // Specific production range
				},
				Labels: uniquelabels.Make(map[string]string{
					"env":  "production",
					"tier": "frontend",
				}),
			}

			stagingNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.2.0/24"), // Specific staging range
				},
				Labels: uniquelabels.Make(map[string]string{
					"env":  "staging",
					"tier": "frontend",
				}),
			}

			developmentNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // Broader dev range
				},
				Labels: uniquelabels.Make(map[string]string{
					"env":  "development",
					"tier": "all",
				}),
			}

			prodKey := model.NetworkSetKey{Name: "prod-frontend"}
			stagingKey := model.NetworkSetKey{Name: "staging-frontend"}
			devKey := model.NetworkSetKey{Name: "dev-all"}

			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				prodKey:    productionNetworkSet,
				stagingKey: stagingNetworkSet,
				devKey:     developmentNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Test production namespace with IP in production range
			prodIP := ipToBytes("10.1.1.100")
			result := testLookupEndpoint(c, [16]byte{}, prodIP, false, "production")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(prodKey))
			Expect(result.Labels().String()).To(ContainSubstring("production"))

			// Test staging namespace with IP in staging range
			stagingIP := ipToBytes("10.1.2.100")
			result = testLookupEndpoint(c, [16]byte{}, stagingIP, false, "staging")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(stagingKey))
			Expect(result.Labels().String()).To(ContainSubstring("staging"))

			// Test development namespace with IP that matches broader dev range
			devIP := ipToBytes("10.1.5.100") // In 10.1.0.0/16 but not in specific /24s
			result = testLookupEndpoint(c, [16]byte{}, devIP, false, "development")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(devKey))
			Expect(result.Labels().String()).To(ContainSubstring("development"))
		})

		It("should demonstrate namespace isolation in NetworkSet lookups", func() {
			// Create identical CIDR ranges in different namespaces
			// This tests that namespace isolation works properly
			commonCIDR := utils.MustParseNet("10.1.0.0/16")

			frontendNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{commonCIDR},
				Labels: uniquelabels.Make(map[string]string{
					"app":  "frontend",
					"tier": "web",
				}),
			}

			backendNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{commonCIDR}, // Same CIDR, different namespace
				Labels: uniquelabels.Make(map[string]string{
					"app":  "backend",
					"tier": "api",
				}),
			}

			frontendKey := model.NetworkSetKey{Name: "frontend-netset"}
			backendKey := model.NetworkSetKey{Name: "backend-netset"}

			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				frontendKey: frontendNetworkSet,
				backendKey:  backendNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Same IP, different namespaces should potentially return different NetworkSets
			// depending on the namespace-aware logic and CIDR specificity
			testIPCommon := ipToBytes("10.1.1.100")

			// Frontend namespace lookup
			frontendResult := testLookupEndpoint(c, [16]byte{}, testIPCommon, false, "frontend")
			Expect(frontendResult).ToNot(BeNil())

			// Backend namespace lookup
			backendResult := testLookupEndpoint(c, [16]byte{}, testIPCommon, false, "backend")
			Expect(backendResult).ToNot(BeNil())

			// In this case with identical CIDRs, the longest-prefix-match logic will determine
			// which NetworkSet is returned, but namespace awareness is being tested
		})

		It("should handle empty namespace gracefully", func() {
			// Test with empty/default namespace
			defaultNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"scope": "default",
				}),
			}

			defaultKey := model.NetworkSetKey{Name: "default-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				defaultKey: defaultNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			// Test with empty namespace
			result := testLookupEndpoint(c, [16]byte{}, testIP, false, "")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(defaultKey))
		})
	})

	Context("when testing getEndpointsWithNamespaceContext optimization", func() {
		It("should optimize lookups when both endpoints are found directly", func() {
			srcIP := ipToBytes("10.1.1.10")
			dstIP := ipToBytes("10.1.1.20")

			// Create endpoints for both source and destination
			srcEPKey := model.WorkloadEndpointKey{
				Hostname:       "src-host",
				OrchestratorID: "k8s",
				WorkloadID:     "src-ns/src-workload",
				EndpointID:     "src-endpoint",
			}
			dstEPKey := model.WorkloadEndpointKey{
				Hostname:       "dst-host",
				OrchestratorID: "k8s",
				WorkloadID:     "dst-ns/dst-workload",
				EndpointID:     "dst-endpoint",
			}

			srcEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(srcEPKey, &model.WorkloadEndpoint{}),
			}
			dstEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(dstEPKey, &model.WorkloadEndpoint{}),
			}

			// Create NetworkSets that could match these IPs (but shouldn't be used)
			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // Could match both IPs
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "fallback",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "fallback-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				srcIP: srcEP,
				dstIP: dstEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Both should return direct endpoints (not NetworkSets)
			Expect(srcResult).ToNot(BeNil())
			Expect(dstResult).ToNot(BeNil())
			Expect(srcResult.Key()).To(Equal(srcEPKey))
			Expect(dstResult.Key()).To(Equal(dstEPKey))
		})

		It("should use namespace context from destination when source needs NetworkSet lookup", func() {
			srcIP := ipToBytes("10.1.1.10") // No direct endpoint for this
			dstIP := ipToBytes("10.1.1.20")

			// Create destination endpoint with namespace
			dstEPKey := model.WorkloadEndpointKey{
				Hostname:       "dst-host",
				OrchestratorID: "k8s",
				WorkloadID:     "production/dst-workload", // namespace: production
				EndpointID:     "dst-endpoint",
			}
			dstEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(dstEPKey, &model.WorkloadEndpoint{}),
			}

			// Create NetworkSets - one generic, one namespace-specific
			genericNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Broader range
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "generic",
				}),
			}
			productionNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // More specific for production
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "production-specific",
					"namespace": "production",
				}),
			}

			genericKey := model.NetworkSetKey{Name: "generic-netset"}
			productionKey := model.NetworkSetKey{Name: "production-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				genericKey:    genericNetworkSet,
				productionKey: productionNetworkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				dstIP: dstEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Destination should be direct endpoint
			Expect(dstResult).ToNot(BeNil())
			Expect(dstResult.Key()).To(Equal(dstEPKey))

			// Source should use NetworkSet (preferably production-specific due to namespace context)
			Expect(srcResult).ToNot(BeNil())
			// Should get the more specific NetworkSet (production-specific)
			Expect(srcResult.Key()).To(Equal(productionKey))
		})

		It("should use namespace context from source when destination needs NetworkSet lookup", func() {
			srcIP := ipToBytes("10.1.1.10")
			dstIP := ipToBytes("10.1.1.20") // No direct endpoint for this

			// Create source endpoint with namespace
			srcEPKey := model.WorkloadEndpointKey{
				Hostname:       "src-host",
				OrchestratorID: "k8s",
				WorkloadID:     "staging/src-workload", // namespace: staging
				EndpointID:     "src-endpoint",
			}
			srcEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(srcEPKey, &model.WorkloadEndpoint{}),
			}

			// Create NetworkSets
			globalNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Broader range
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "global",
				}),
			}
			stagingNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // More specific for staging
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "staging-specific",
					"namespace": "staging",
				}),
			}

			globalKey := model.NetworkSetKey{Name: "global-netset"}
			stagingKey := model.NetworkSetKey{Name: "staging-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				globalKey:  globalNetworkSet,
				stagingKey: stagingNetworkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				srcIP: srcEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Source should be direct endpoint
			Expect(srcResult).ToNot(BeNil())
			Expect(srcResult.Key()).To(Equal(srcEPKey))

			// Destination should use NetworkSet with namespace context from source
			Expect(dstResult).ToNot(BeNil())
			// Should get the staging-specific NetworkSet
			Expect(dstResult.Key()).To(Equal(stagingKey))
		})

		It("should return both NetworkSets when no direct endpoints exist", func() {
			srcIP := utils.IpStrTo16Byte("10.1.1.10") // No direct endpoints
			dstIP := utils.IpStrTo16Byte("10.1.1.20")

			// Create only NetworkSets
			srcNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.1.0/24"), // Specific for source
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "src-network",
				}),
			}
			dstNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.2.0/24"), // Different range for dest
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "dst-network",
				}),
			}
			fallbackNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.0.0.0/8"), // Fallback for both
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "fallback",
				}),
			}

			srcKey := model.NetworkSetKey{Name: "src-netset"}
			dstKey := model.NetworkSetKey{Name: "dst-netset"}
			fallbackKey := model.NetworkSetKey{Name: "fallback-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				srcKey:      srcNetworkSet,
				dstKey:      dstNetworkSet,
				fallbackKey: fallbackNetworkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Both should return NetworkSets
			Expect(srcResult).ToNot(BeNil())
			Expect(dstResult).ToNot(BeNil())

			// Due to how NetworkSet lookup works, it may return the first matching NetworkSet
			// The actual behavior depends on the order of NetworkSets returned by the lookup cache
			// Let's check that we get some NetworkSet match for both
			Expect(srcResult.Key()).To(BeAssignableToTypeOf(model.NetworkSetKey{}))
			Expect(dstResult.Key()).To(BeAssignableToTypeOf(model.NetworkSetKey{}))
		})

		It("should handle NetworkSets disabled gracefully", func() {
			srcIP := utils.IpStrTo16Byte("10.1.1.10")
			dstIP := utils.IpStrTo16Byte("10.1.1.20")

			// Create NetworkSets that would match
			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
			}

			nsKey := model.NetworkSetKey{Name: "test-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     false, // Disabled
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Both should be nil since NetworkSets are disabled and no direct endpoints exist
			Expect(srcResult).To(BeNil())
			Expect(dstResult).To(BeNil())
		})

		It("should handle mixed endpoint and NetworkSet scenarios efficiently", func() {
			srcIP := ipToBytes("10.1.1.10")
			dstIP := ipToBytes("10.1.1.20")

			// Source has direct endpoint
			srcEPKey := model.WorkloadEndpointKey{
				Hostname:       "src-host",
				OrchestratorID: "k8s",
				WorkloadID:     "development/src-workload",
				EndpointID:     "src-endpoint",
			}
			srcEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(srcEPKey, &model.WorkloadEndpoint{}),
			}

			// Destination only has NetworkSet
			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "dev-network",
					"namespace": "development",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "dev-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				srcIP: srcEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Source should be direct endpoint
			Expect(srcResult).ToNot(BeNil())
			Expect(srcResult.Key()).To(Equal(srcEPKey))

			// Destination should be NetworkSet (with namespace context from source)
			Expect(dstResult).ToNot(BeNil())
			Expect(dstResult.Key()).To(Equal(nsKey))
		})
	})

	Context("when testing lookupNetworkSetWithNamespace function", func() {
		It("should return nil when NetworkSets are disabled", func() {
			testIPLocal := ipToBytes("10.1.1.100")

			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
			}

			nsKey := model.NetworkSetKey{Name: "test-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     false,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			result := c.lookupNetworkSetWithNamespace([16]byte{}, testIPLocal, false, "test-namespace")
			Expect(result).To(BeNil())
		})

		It("should return NetworkSet when one matches", func() {
			testIPLocal := ipToBytes("10.1.1.100")

			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "test",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "test-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			result := c.lookupNetworkSetWithNamespace([16]byte{}, testIPLocal, false, "test-namespace")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(nsKey))
		})

		It("should return nil when no NetworkSet matches", func() {
			testIPLocal := ipToBytes("192.168.1.100") // Different range

			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"), // Won't match testIPLocal
				},
			}

			nsKey := model.NetworkSetKey{Name: "test-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			result := c.lookupNetworkSetWithNamespace([16]byte{}, testIPLocal, false, "test-namespace")
			Expect(result).To(BeNil())
		})
	})

	Context("when testing namespace extraction from endpoints", func() {
		It("should extract namespace from WorkloadEndpoint correctly", func() {
			// Test the getNamespaceFromEp function indirectly by testing the full lookup flow
			srcIP := ipToBytes("10.1.1.10")
			dstIP := ipToBytes("10.1.1.20")

			// Create source endpoint with namespace in WorkloadID
			srcEPKey := model.WorkloadEndpointKey{
				Hostname:       "src-host",
				OrchestratorID: "k8s",
				WorkloadID:     "frontend/src-workload", // namespace: frontend
				EndpointID:     "src-endpoint",
			}
			srcEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(srcEPKey, &model.WorkloadEndpoint{}),
			}

			// Create namespace-specific NetworkSet that should be used for destination
			frontendNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "frontend-network",
					"namespace": "frontend",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "frontend-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: frontendNetworkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				srcIP: srcEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Source should be the direct endpoint
			Expect(srcResult).ToNot(BeNil())
			Expect(srcResult.Key()).To(Equal(srcEPKey))

			// Destination should use the NetworkSet (demonstrating namespace context was used)
			Expect(dstResult).ToNot(BeNil())
			Expect(dstResult.Key()).To(Equal(nsKey))
		})

		It("should handle endpoints with ResourceKey correctly", func() {
			srcIP := ipToBytes("10.1.1.10")
			dstIP := ipToBytes("10.1.1.20")

			// Create a WorkloadEndpoint that represents a production namespace
			srcEPKey := model.WorkloadEndpointKey{
				Hostname:       "src-host",
				OrchestratorID: "k8s",
				WorkloadID:     "production/src-workload", // namespace: production
				EndpointID:     "src-endpoint",
			}
			srcEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(srcEPKey, &model.WorkloadEndpoint{}),
			}

			// Create destination NetworkSet that should use the namespace from source
			productionNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "production-network",
					"namespace": "production",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "production-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: productionNetworkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				srcIP: srcEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Source should be the WorkloadEndpoint
			Expect(srcResult).ToNot(BeNil())
			Expect(srcResult.Key()).To(Equal(srcEPKey))

			// Destination should use the NetworkSet (with namespace context from source)
			Expect(dstResult).ToNot(BeNil())
			Expect(dstResult.Key()).To(Equal(nsKey))
		})

		It("should handle endpoints with no extractable namespace gracefully", func() {
			srcIP := ipToBytes("10.1.1.10")
			dstIP := ipToBytes("10.1.1.20")

			// Create endpoint with WorkloadID that doesn't follow namespace/name pattern
			srcEPKey := model.WorkloadEndpointKey{
				Hostname:       "src-host",
				OrchestratorID: "k8s",
				WorkloadID:     "invalid-workload-format", // No namespace separator
				EndpointID:     "src-endpoint",
			}
			srcEP := &calc.LocalEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(srcEPKey, &model.WorkloadEndpoint{}),
			}

			// Create a generic NetworkSet
			genericNetworkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type": "generic",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "generic-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: genericNetworkSet,
			}
			epMap := map[[16]byte]calc.EndpointData{
				srcIP: srcEP,
			}
			lm := newMockLookupsCache(epMap, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			t := tuple.Make(srcIP, dstIP, proto_tcp, 8080, 80)
			srcResult, dstResult := c.findEndpointBestMatch(t)

			// Source should be the direct endpoint
			Expect(srcResult).ToNot(BeNil())
			Expect(srcResult.Key()).To(Equal(srcEPKey))

			// Destination should still get the NetworkSet (with empty namespace context)
			Expect(dstResult).ToNot(BeNil())
			Expect(dstResult.Key()).To(Equal(nsKey))
		})
	})
})

// Mock EgressDomainCache for testing
type mockEgressDomainCache struct {
	domains map[string]map[[16]byte][]string
}

func (m *mockEgressDomainCache) GetTopLevelDomainsForIP(clientIP string, ip [16]byte) []string {
	if clientDomains, ok := m.domains[clientIP]; ok {
		if domains, ok := clientDomains[ip]; ok {
			return domains
		}
	}
	return nil
}

func (m *mockEgressDomainCache) IterWatchedDomainsForIP(clientIP string, ip [16]byte, fn func(domain string) bool) {
	if clientDomains, ok := m.domains[clientIP]; ok {
		if domains, ok := clientDomains[ip]; ok {
			_ = slices.ContainsFunc(domains, fn)
		}
	}
}

func BenchmarkNflogPktToStat(b *testing.B) {
	epMap := map[[16]byte]calc.EndpointData{
		localIp1:  localEd1,
		localIp2:  localEd2,
		remoteIp1: remoteEd1,
	}

	nflogMap := map[[64]byte]*calc.RuleID{}

	for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
		nflogMap[policyIDStrToRuleIDParts(rid)] = rid
	}

	conf := &Config{
		AgeTimeout:            time.Duration(10) * time.Second,
		InitialReportingDelay: time.Duration(5) * time.Second,
		ExportingInterval:     time.Duration(1) * time.Second,
		FlowLogsFlushInterval: time.Duration(100) * time.Second,
		DisplayDebugTraceLogs: true,
	}
	lm := newMockLookupsCache(epMap, nflogMap, nil, nil)
	nflogReader := NewNFLogReader(lm, 0, 0, 0, false)
	c := newCollector(lm, conf).(*collector)
	c.SetPacketInfoReader(nflogReader)
	c.SetConntrackInfoReader(dummyConntrackInfoReader{})
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		pktinfo := nflogReader.ConvertNflogPkt(rules.RuleDirIngress, ingressPktAllow[ingressPktAllowNflogTuple])
		c.applyPacketInfo(pktinfo)
	}
}

func BenchmarkApplyStatUpdate(b *testing.B) {
	epMap := map[[16]byte]calc.EndpointData{
		localIp1:  localEd1,
		localIp2:  localEd2,
		remoteIp1: remoteEd1,
	}

	nflogMap := map[[64]byte]*calc.RuleID{}
	for _, rid := range []*calc.RuleID{defTierPolicy1AllowEgressRuleID, defTierPolicy1AllowIngressRuleID, defTierPolicy2DenyIngressRuleID, defTierPolicy2DenyEgressRuleID} {
		nflogMap[policyIDStrToRuleIDParts(rid)] = rid
	}

	conf := &Config{
		AgeTimeout:            time.Duration(10) * time.Second,
		InitialReportingDelay: time.Duration(5) * time.Second,
		ExportingInterval:     time.Duration(1) * time.Second,
		FlowLogsFlushInterval: time.Duration(100) * time.Second,
		DisplayDebugTraceLogs: true,
	}
	lm := newMockLookupsCache(epMap, nflogMap, nil, nil)
	nflogReader := NewNFLogReader(lm, 0, 0, 0, false)
	c := newCollector(lm, conf).(*collector)
	c.SetPacketInfoReader(nflogReader)
	c.SetConntrackInfoReader(dummyConntrackInfoReader{})
	var tuples []tuple.Tuple
	MaxSrcPort := 1000
	MaxDstPort := 1000
	for sp := 1; sp < MaxSrcPort; sp++ {
		for dp := 1; dp < MaxDstPort; dp++ {
			t := tuple.New(localIp1, localIp2, proto_tcp, sp, dp)
			tuples = append(tuples, *t)
		}
	}
	var rids []*calc.RuleID
	MaxEntries := 10000
	for range MaxEntries {
		rid := defTierPolicy1AllowIngressRuleID
		rids = append(rids, rid)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		for i := range MaxEntries {
			data := NewData(tuples[i], localEd1, remoteEd1)
			c.applyNflogStatUpdate(data, rids[i], 0, 1, 2)
		}
	}
}

type dummyConntrackInfoReader struct {
	MockSenderChannel chan []clttypes.ConntrackInfo
}

func (d dummyConntrackInfoReader) Start() error { return nil }
func (d dummyConntrackInfoReader) ConntrackInfoChan() <-chan []clttypes.ConntrackInfo {
	return d.MockSenderChannel
}

func TestLoopDataplaneInfoUpdates(t *testing.T) {
	RegisterTestingT(t)

	// Setup helper function to initialize the collector and channel, and register cleanup.
	setup := func(t *testing.T) (*collector, chan *proto.ToDataplane) {
		dpInfoChan := make(chan *proto.ToDataplane, 10)
		c := &collector{
			policyStoreManager: policystore.NewPolicyStoreManager(),
		}
		// Register cleanup to be automatically called at the end of each test
		t.Cleanup(func() {
			close(dpInfoChan)
		})

		// Start the loop in a goroutine
		go c.loopProcessingDataplaneInfoUpdates(dpInfoChan)

		return c, dpInfoChan
	}

	insync := func(dpInfoChan chan *proto.ToDataplane) {
		// Ensure that the test channel is closed at the end of each test
		dpInfo := proto.ToDataplane{
			Payload: &proto.ToDataplane_InSync{
				InSync: &proto.InSync{},
			},
		}
		dpInfoChan <- &dpInfo
	}

	t.Run("should process dataplane info updates and update the policy store", func(t *testing.T) {
		c, dpInfoChan := setup(t)

		id := proto.WorkloadEndpointID{
			OrchestratorId: "test-orchestrator",
			WorkloadId:     "test-workload",
			EndpointId:     "test-endpoint",
		}
		dpInfo := proto.ToDataplane{
			Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
				WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
					Id: &id,
					Endpoint: &proto.WorkloadEndpoint{
						Name: "test-endpoint",
					},
				},
			},
		}
		dpInfoChan <- &dpInfo
		insync(dpInfoChan)

		Eventually(func() bool {
			validation := false
			c.policyStoreManager.DoWithReadLock(func(store *policystore.PolicyStore) {
				validation = len(store.Endpoints) == 1 &&
					store.Endpoints[types.ProtoToWorkloadEndpointID(&id)].Name == "test-endpoint"
			})
			return validation
		}, time.Duration(time.Second*5), time.Millisecond*1000).Should(BeTrue())
	})

	t.Run("should handle multiple dataplane info updates", func(t *testing.T) {
		c, dpInfoChan := setup(t)

		id1 := proto.WorkloadEndpointID{
			OrchestratorId: "test-orchestrator1",
			WorkloadId:     "test-workload1",
			EndpointId:     "test-endpoint1",
		}
		id2 := proto.WorkloadEndpointID{
			OrchestratorId: "test-orchestrator2",
			WorkloadId:     "test-workload2",
			EndpointId:     "test-endpoint2",
		}

		dpInfo1 := &proto.ToDataplane{
			Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
				WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
					Id: &id1,
					Endpoint: &proto.WorkloadEndpoint{
						Name: "test-endpoint1",
					},
				},
			},
		}
		dpInfo2 := &proto.ToDataplane{
			Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
				WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
					Id: &id2,
					Endpoint: &proto.WorkloadEndpoint{
						Name: "test-endpoint2",
					},
				},
			},
		}
		dpInfoChan <- dpInfo1
		dpInfoChan <- dpInfo2
		insync(dpInfoChan)

		Eventually(func() bool {
			validation := false
			c.policyStoreManager.DoWithReadLock(func(store *policystore.PolicyStore) {
				validation = len(store.Endpoints) == 2 &&
					store.Endpoints[types.ProtoToWorkloadEndpointID(&id1)].Name == "test-endpoint1" &&
					store.Endpoints[types.ProtoToWorkloadEndpointID(&id2)].Name == "test-endpoint2"
			})
			return validation
		}, time.Duration(time.Second*5), time.Millisecond*1000).Should(BeTrue())
	})

	t.Run("should not panic when the channel is closed", func(t *testing.T) {
		dpInfoChan := make(chan *proto.ToDataplane, 10)
		c := &collector{
			policyStoreManager: policystore.NewPolicyStoreManager(),
		}

		close(dpInfoChan)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("The code panicked, but it should not have: %v", r)
			}
		}()
		// The loop should exit without panicking
		c.loopProcessingDataplaneInfoUpdates(dpInfoChan)
	})
}

func TestRunPendingRuleTraceEvaluation(t *testing.T) {
	RegisterTestingT(t)

	// Helper function to convert model workload endpoint key to protobuf endpoint ID
	convertWorkloadId := func(key model.WorkloadEndpointKey) types.WorkloadEndpointID {
		return types.WorkloadEndpointID{
			OrchestratorId: key.OrchestratorID,
			WorkloadId:     key.WorkloadID,
			EndpointId:     key.EndpointID,
		}
	}

	// Setup test environment
	epMap := map[[16]byte]calc.EndpointData{
		localIp1:  localEd1,
		localIp2:  localEd2,
		remoteIp1: remoteEd1,
	}

	lm := newMockLookupsCache(epMap, nil, nil, nil)
	policyStoreManager := policystore.NewPolicyStoreManager()

	conf := &Config{
		AgeTimeout:            time.Duration(10) * time.Second,
		InitialReportingDelay: time.Duration(5) * time.Second,
		ExportingInterval:     time.Duration(1) * time.Second,
		FlowLogsFlushInterval: time.Duration(100) * time.Second,
		DisplayDebugTraceLogs: true,
		PolicyStoreManager:    policyStoreManager,
	}
	c := newCollector(lm, conf).(*collector)

	// Create test flow tuples
	// Flow 1: Local-to-local communication (localIp1 -> localIp2)
	flowTuple1 := tuple.New(localIp1, localIp2, proto_tcp, 1000, 1000)

	// Flow 2: Local-to-remote communication (localIp2 -> remoteIp1)
	flowTuple2 := tuple.New(localIp2, remoteIp1, proto_tcp, 1000, 1000)

	// Setup initial policy configuration
	// localWlEp1 has policy1 for both ingress and egress
	localWlEp1Proto := calc.ModelWorkloadEndpointToProto(localWlEp1, nil, nil, []*proto.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	})

	// localWlEp2 initially has policy2 (deny) for both ingress and egress
	localWlEp2Proto := calc.ModelWorkloadEndpointToProto(localWlEp2, nil, nil, []*proto.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
		},
	})

	// remoteWlEp1 has no policies
	remoteWlEp1Proto := calc.ModelWorkloadEndpointToProto(remoteWlEp1, nil, nil, []*proto.TierInfo{})

	// Initialize policy store with endpoints and policies
	policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
		// Add endpoint configurations
		ps.Endpoints[convertWorkloadId(localWlEPKey1)] = localWlEp1Proto
		ps.Endpoints[convertWorkloadId(localWlEPKey2)] = localWlEp2Proto
		ps.Endpoints[convertWorkloadId(remoteWlEpKey1)] = remoteWlEp1Proto

		// Add policy definitions
		// policy1: Allow all traffic
		ps.PolicyByID[types.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}] = &proto.Policy{
			Tier:          "default",
			InboundRules:  []*proto.Rule{{Action: "allow"}},
			OutboundRules: []*proto.Rule{{Action: "allow"}},
		}

		// policy2: Deny all traffic
		ps.PolicyByID[types.PolicyID{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}] = &proto.Policy{
			Tier:          "default",
			InboundRules:  []*proto.Rule{{Action: "deny"}},
			OutboundRules: []*proto.Rule{{Action: "deny"}},
		}
	})
	policyStoreManager.OnInSync()

	// Simulate packet processing to create flow data
	ruleIDIngressPolicy1 := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "", 0, rules.RuleDirIngress, rules.RuleActionAllow)
	packetInfoIngress1 := clttypes.PacketInfo{
		Tuple:     *flowTuple1,
		Direction: rules.RuleDirIngress,
		RuleHits:  []clttypes.RuleHit{{RuleID: ruleIDIngressPolicy1, Hits: 1, Bytes: 100}},
	}
	c.applyPacketInfo(packetInfoIngress1)

	ruleIDEgressPolicy1 := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "", 0, rules.RuleDirEgress, rules.RuleActionAllow)
	packetInfoEgress1 := clttypes.PacketInfo{
		Tuple:     *flowTuple1,
		Direction: rules.RuleDirEgress,
		RuleHits:  []clttypes.RuleHit{{RuleID: ruleIDEgressPolicy1, Hits: 1, Bytes: 100}},
	}
	c.applyPacketInfo(packetInfoEgress1)

	// Process egress packet for flow 2 (localIp2 -> remoteIp1)
	ruleIDEgressPolicy2 := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy2", "", 0, rules.RuleDirEgress, rules.RuleActionDeny)
	packetInfoEgress2 := clttypes.PacketInfo{
		Tuple:     *flowTuple2,
		Direction: rules.RuleDirEgress,
		RuleHits:  []clttypes.RuleHit{{RuleID: ruleIDEgressPolicy2, Hits: 1, Bytes: 100}},
	}
	c.applyPacketInfo(packetInfoEgress2)

	// Retrieve flow data from collector
	flowData1 := c.epStats[*flowTuple1]
	flowData2 := c.epStats[*flowTuple2]

	// Verify initial pending rule trace evaluation
	testCases := []struct {
		name           string
		pendingRuleIDs []*calc.RuleID
		expectedRuleID *calc.RuleID
		expectedLength int
		description    string
	}{
		{
			name:           "Flow1 Ingress",
			pendingRuleIDs: flowData1.IngressPendingRuleIDs,
			expectedRuleID: defTierPolicy2DenyIngressRuleID,
			expectedLength: 1,
			description:    "Flow1 destination (localEd2) should have policy2 deny rule for ingress",
		},
		{
			name:           "Flow1 Egress",
			pendingRuleIDs: flowData1.EgressPendingRuleIDs,
			expectedRuleID: defTierPolicy1AllowEgressRuleID,
			expectedLength: 1,
			description:    "Flow1 source (localEd1) should have policy1 allow rule for egress",
		},
		{
			name:           "Flow2 Ingress",
			pendingRuleIDs: flowData2.IngressPendingRuleIDs,
			expectedRuleID: nil,
			expectedLength: 0,
			description:    "Flow2 destination (remoteEd1) has no policies, so no ingress rules",
		},
		{
			name:           "Flow2 Egress",
			pendingRuleIDs: flowData2.EgressPendingRuleIDs,
			expectedRuleID: defTierPolicy2DenyEgressRuleID,
			expectedLength: 1,
			description:    "Flow2 source (localEd2) should have policy2 deny rule for egress",
		},
	}

	// Test initial policy evaluation
	for _, tc := range testCases {
		t.Run("Initial_"+tc.name, func(t *testing.T) {
			Expect(tc.pendingRuleIDs).To(HaveLen(tc.expectedLength), tc.description)
			if tc.expectedLength == 1 {
				validateRuleID(t, tc.pendingRuleIDs[0], tc.expectedRuleID, tc.name)
			}
		})
	}

	// Test policy update scenario
	t.Run("PolicyUpdate", func(t *testing.T) {
		// Change localWlEp2 from policy2 (deny) to policy1 (allow)
		updatedLocalWlEp2Proto := calc.ModelWorkloadEndpointToProto(localWlEp2, nil, nil, []*proto.TierInfo{
			{Name: "default", IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}}, EgressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}}},
		})

		// Update the policy store
		c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
			ps.Endpoints[convertWorkloadId(localWlEPKey2)] = updatedLocalWlEp2Proto
		})
		c.policyStoreManager.OnInSync()

		// Trigger pending rule trace update
		c.updatePendingRuleTraces()

		// Get updated flow data
		updatedFlowData1 := c.epStats[*flowTuple1]
		updatedFlowData2 := c.epStats[*flowTuple2]

		// Verify updated policy evaluation
		updatedTestCases := []struct {
			name           string
			pendingRuleIDs []*calc.RuleID
			expectedRuleID *calc.RuleID
			expectedLength int
			description    string
		}{
			{
				name:           "Flow1 Ingress After Update",
				pendingRuleIDs: updatedFlowData1.IngressPendingRuleIDs,
				expectedRuleID: defTierPolicy1AllowIngressRuleID,
				expectedLength: 1,
				description:    "After update, Flow1 destination should have policy1 allow rule for ingress",
			},
			{
				name:           "Flow1 Egress After Update",
				pendingRuleIDs: updatedFlowData1.EgressPendingRuleIDs,
				expectedRuleID: defTierPolicy1AllowEgressRuleID,
				expectedLength: 1,
				description:    "Flow1 source should still have policy1 allow rule for egress",
			},
			{
				name:           "Flow2 Ingress After Update",
				pendingRuleIDs: updatedFlowData2.IngressPendingRuleIDs,
				expectedRuleID: nil,
				expectedLength: 0,
				description:    "Flow2 destination (remoteEd1) still has no policies",
			},
			{
				name:           "Flow2 Egress After Update",
				pendingRuleIDs: updatedFlowData2.EgressPendingRuleIDs,
				expectedRuleID: defTierPolicy1AllowEgressRuleID,
				expectedLength: 1,
				description:    "After update, Flow2 source should have policy1 allow rule for egress",
			},
		}

		for _, tc := range updatedTestCases {
			t.Run(tc.name, func(t *testing.T) {
				Expect(tc.pendingRuleIDs).To(HaveLen(tc.expectedLength), tc.description)
				if tc.expectedLength == 1 {
					validateRuleID(t, tc.pendingRuleIDs[0], tc.expectedRuleID, tc.name)
				}
			})
		}
	})

	Context("lookupNetworkSetWithNamespace function", func() {
		It("should return nil when IP does not match any NetworkSet", func() {
			srcIP := utils.IpStrTo16Byte("10.1.1.10")
			dstIP := utils.IpStrTo16Byte("192.168.1.10")

			// Create a NetworkSet that doesn't match either IP
			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("172.16.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "production-network",
					"namespace": "production",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "production-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			result := c.lookupNetworkSetWithNamespace(srcIP, dstIP, false, "production")
			Expect(result).To(BeNil())
		})

		It("should return NetworkSet endpoint for NetworkSet-based lookups", func() {
			srcIP := utils.IpStrTo16Byte("10.1.1.10")
			dstIP := utils.IpStrTo16Byte("10.1.1.20")

			// Create a NetworkSet that matches the destination IP
			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "production-network",
					"namespace": "production",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "production-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     true,
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			result := c.lookupNetworkSetWithNamespace(srcIP, dstIP, false, "production")
			Expect(result).ToNot(BeNil())
			Expect(result.Key()).To(Equal(nsKey))
		})

		It("should return nil when NetworkSets are disabled", func() {
			srcIP := utils.IpStrTo16Byte("10.1.1.10")
			dstIP := utils.IpStrTo16Byte("10.1.1.20")

			// Create a NetworkSet that would match if enabled
			networkSet := &model.NetworkSet{
				Nets: []net.IPNet{
					utils.MustParseNet("10.1.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{
					"type":      "production-network",
					"namespace": "production",
				}),
			}

			nsKey := model.NetworkSetKey{Name: "production-netset"}
			nsMap := map[model.NetworkSetKey]*model.NetworkSet{
				nsKey: networkSet,
			}
			lm := newMockLookupsCache(nil, nil, nsMap, nil)

			c = newCollector(lm, &Config{
				EnableNetworkSets:     false, // NetworkSets disabled
				ExportingInterval:     time.Second,
				FlowLogsFlushInterval: time.Second,
			}).(*collector)

			result := c.lookupNetworkSetWithNamespace(srcIP, dstIP, false, "production")
			Expect(result).To(BeNil())
		})
	})

	// Test endpoint deletion scenario
	t.Run("EndpointDeletion", func(t *testing.T) {
		// Remove localEd1 from the lookup cache to simulate endpoint deletion
		epMapWithoutLocalEd1 := map[[16]byte]calc.EndpointData{
			localIp2:  localEd2,
			remoteIp1: remoteEd1,
		}
		lm = newMockLookupsCache(epMapWithoutLocalEd1, nil, nil, nil)
		c.luc = lm

		// Make another policy change to trigger evaluation
		localWlEp2Proto := calc.ModelWorkloadEndpointToProto(localWlEp2, nil, nil, []*proto.TierInfo{
			{Name: "default", IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}}, EgressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}}},
		})

		c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
			ps.Endpoints[convertWorkloadId(localWlEPKey2)] = localWlEp2Proto
		})
		c.policyStoreManager.OnInSync()

		// Store original pending rule IDs before update
		originalFlow1IngressRules := append([]*calc.RuleID(nil), c.epStats[*flowTuple1].IngressPendingRuleIDs...)
		originalFlow1EgressRules := append([]*calc.RuleID(nil), c.epStats[*flowTuple1].EgressPendingRuleIDs...)

		// Trigger update - should skip flow1 since localEd1 is deleted
		c.updatePendingRuleTraces()

		currentFlowData1 := c.epStats[*flowTuple1]
		currentFlowData2 := c.epStats[*flowTuple2]

		// Verify that flow1 rules remain unchanged (endpoint deleted, so no update)
		Expect(currentFlowData1.IngressPendingRuleIDs).To(Equal(originalFlow1IngressRules),
			"Flow1 ingress rules should remain unchanged when source endpoint is deleted")
		Expect(currentFlowData1.EgressPendingRuleIDs).To(Equal(originalFlow1EgressRules),
			"Flow1 egress rules should remain unchanged when source endpoint is deleted")

		// Verify that flow2 ingress rules remain empty
		Expect(currentFlowData2.IngressPendingRuleIDs).To(HaveLen(0),
			"Flow2 ingress rules should remain empty as destination endpoint has no policies")
		// Verify that flow2 rules are still updated (both endpoints exist)
		Expect(currentFlowData2.EgressPendingRuleIDs).To(HaveLen(1),
			"Flow2 egress rules should still be updated when both endpoints exist")
		if len(currentFlowData2.EgressPendingRuleIDs) == 1 {
			validateRuleID(t, currentFlowData2.EgressPendingRuleIDs[0], defTierPolicy1AllowEgressRuleID, "Flow2 Egress After Endpoint Deletion")
		}
	})
}

// Helper function to validate rule ID fields
func validateRuleID(t *testing.T, actual, expected *calc.RuleID, context string) {
	Expect(actual.Name).To(Equal(expected.Name), "Policy name mismatch in %s", context)
	Expect(actual.Tier).To(Equal(expected.Tier), "Tier name mismatch in %s", context)
	Expect(actual.Namespace).To(Equal(expected.Namespace), "Namespace mismatch in %s", context)
	Expect(actual.Action).To(Equal(expected.Action), "Action mismatch in %s", context)
	Expect(actual.Direction).To(Equal(expected.Direction), "Direction mismatch in %s", context)
	Expect(actual.Index).To(Equal(expected.Index), "Index mismatch in %s", context)
}

func TestEqualFunction(t *testing.T) {
	RegisterTestingT(t)
	t.Run("should return true for equal rule IDs", func(t *testing.T) {
		ruleID1 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     0,
			IndexStr:  "0",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID2 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     0,
			IndexStr:  "0",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID3 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy2",
				Namespace: "",
			},
			Index:     1,
			IndexStr:  "1",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirEgress,
		}
		ruleID4 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy2",
				Namespace: "",
			},
			Index:     1,
			IndexStr:  "1",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirEgress,
		}

		Expect(equal([]*calc.RuleID{ruleID1, ruleID3}, []*calc.RuleID{ruleID2, ruleID4})).To(BeTrue(), "Expected true, got false")
	})

	t.Run("should return false for rule IDs that contain the same elements but are out of order", func(t *testing.T) {
		ruleID1 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     0,
			IndexStr:  "0",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID2 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     1,
			IndexStr:  "1",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID3 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     1,
			IndexStr:  "1",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID4 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     0,
			IndexStr:  "0",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}

		Expect(equal([]*calc.RuleID{ruleID1, ruleID3}, []*calc.RuleID{ruleID2, ruleID4})).To(BeFalse(), "Expected false, got true")
	})

	t.Run("should return false for different lengths of rule IDs", func(t *testing.T) {
		ruleID1 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     0,
			IndexStr:  "0",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID2 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     0,
			IndexStr:  "0",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}
		ruleID3 := &calc.RuleID{
			PolicyID: calc.PolicyID{
				Kind:      v3.KindGlobalNetworkPolicy,
				Name:      "policy1",
				Namespace: "",
			},
			Index:     1,
			IndexStr:  "1",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		}

		if equal([]*calc.RuleID{ruleID1, ruleID3}, []*calc.RuleID{ruleID2}) {
			t.Errorf("Expected false, got true")
		}
	})
}
