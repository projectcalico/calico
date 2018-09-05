// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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

package v3_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/validator/v3"
)

func init() {
	// We need some pointers to ints, so just define as values here.
	var V0 = 0
	var V4 = 4
	var V6 = 6
	var V128 = 128
	var V254 = 254
	var V255 = 255
	var V256 = 256

	// Set up some values we use in various tests.
	ipv4_1 := "1.2.3.4"
	ipv4_2 := "100.200.0.0"
	ipv6_1 := "aabb:aabb::ffff"
	ipv6_2 := "aabb::abcd"
	netv4_1 := "1.2.3.4/32"
	netv4_2 := "1.2.0.0/32"
	netv4_3 := "1.2.3.0/26"
	netv4_4 := "1.0.0.0/10"
	netv4_5 := "1.2.3.0/27"
	netv6_1 := "aabb:aabb::ffff/128"
	netv6_2 := "aabb:aabb::/128"
	netv6_3 := "aabb:aabb::0000/122"
	netv6_4 := "aa00:0000::0000/10"

	bad_ipv4_1 := "999.999.999.999"
	bad_ipv6_1 := "xyz:::"

	protoTCP := numorstring.ProtocolFromString("TCP")
	protoUDP := numorstring.ProtocolFromString("UDP")
	protoNumeric := numorstring.ProtocolFromInt(123)

	as61234, _ := numorstring.ASNumberFromString("61234")

	// longLabelsValue is 63 and 64 chars long
	maxAnnotationsLength := 256 * (1 << 10)
	longValue := make([]byte, maxAnnotationsLength)
	for i := range longValue {
		longValue[i] = 'x'
	}
	value63 := string(longValue[:63])
	value64 := string(longValue[:64])

	// Max name length
	maxNameLength := 253

	// Perform validation on error messages from validator
	DescribeTable("Validator errors",
		func(input interface{}, e string) {
			err := v3.Validate(input)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(e))
		},
		Entry("should reject Rule with invalid port (name + number)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{{
						MinPort: 0,
						MaxPort: 456,
					}},
				},
			}, "error with field Port = '0' (port range invalid, port number must be between 1 and 65535)"),
	)

	// Perform basic validation of different fields and structures to test simple valid/invalid
	// scenarios.  This does not test precise error strings - but does cover a lot of the validation
	// code paths.
	DescribeTable("Validator",
		func(input interface{}, valid bool) {
			if valid {
				Expect(v3.Validate(input)).NotTo(HaveOccurred(),
					"expected value to be valid")
			} else {
				Expect(v3.Validate(input)).To(HaveOccurred(),
					"expected value to be invalid")
			}
		},

		// (API) Actions.
		Entry("should accept allow action", api.Rule{Action: "Allow"}, true),
		Entry("should accept deny action", api.Rule{Action: "Deny"}, true),
		Entry("should accept log action", api.Rule{Action: "Log"}, true),
		Entry("should reject unknown action", api.Rule{Action: "unknown"}, false),
		Entry("should reject unknown action", api.Rule{Action: "allowfoo"}, false),
		Entry("should reject rule with no action", api.Rule{}, false),

		// (API model) EndpointPorts.
		Entry("should accept EndpointPort with tcp protocol", api.EndpointPort{
			Name:     "a-valid-port",
			Protocol: protoTCP,
			Port:     1234,
		}, true),
		Entry("should accept EndpointPort with udp protocol", api.EndpointPort{
			Name:     "a-valid-port",
			Protocol: protoUDP,
			Port:     1234,
		}, true),
		Entry("should reject EndpointPort with empty name", api.EndpointPort{
			Name:     "",
			Protocol: protoUDP,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no protocol", api.EndpointPort{
			Name: "a-valid-port",
			Port: 1234,
		}, false),
		Entry("should reject EndpointPort with numeric protocol", api.EndpointPort{
			Name:     "a-valid-port",
			Protocol: protoNumeric,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no port", api.EndpointPort{
			Name:     "a-valid-port",
			Protocol: protoTCP,
		}, false),

		// (API) WorkloadEndpointSpec.
		Entry("should accept WorkloadEndpointSpec with a port (m)",
			api.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Name:     "a-valid-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			true,
		),
		Entry("should reject WorkloadEndpointSpec with an unnamed port (m)",
			api.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should accept WorkloadEndpointSpec with name-clashing ports (m)",
			api.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Name:     "a-valid-port",
						Protocol: protoTCP,
						Port:     1234,
					},
					{
						Name:     "a-valid-port",
						Protocol: protoUDP,
						Port:     5456,
					},
				},
			},
			true,
		),

		// (API) HostEndpointSpec.
		Entry("should accept HostEndpointSpec with a port (m)",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Name:     "a-valid-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
				Node: "node01",
			},
			true,
		),
		Entry("should reject HostEndpointSpec with an unnamed port (m)",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
				Node: "node01",
			},
			false,
		),
		Entry("should reject HostEndpointSpec with a missing node",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Name:     "a-valid-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should accept HostEndpointSpec with name-clashing ports (m)",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Ports: []api.EndpointPort{
					{
						Name:     "a-valid-port",
						Protocol: protoTCP,
						Port:     1234,
					},
					{
						Name:     "a-valid-port",
						Protocol: protoUDP,
						Port:     5456,
					},
				},
				Node: "node01",
			},
			true,
		),

		Entry("should accept GlobalNetworkSetSpec with CIDRs and IPs",
			api.GlobalNetworkSetSpec{
				Nets: []string{
					"10.0.0.1",
					"11.0.0.0/8",
					"dead:beef::",
					"dead:beef::/96",
				},
			},
			true,
		),
		Entry("should reject GlobalNetworkSetSpec with bad CIDR",
			api.GlobalNetworkSetSpec{
				Nets: []string{
					"garbage",
				},
			},
			false,
		),
		Entry("should accept GlobalNetworkSet with labels",
			api.GlobalNetworkSet{
				ObjectMeta: v1.ObjectMeta{
					Name: "testset",
					Labels: map[string]string{
						"a": "b",
					},
				},
				Spec: api.GlobalNetworkSetSpec{
					Nets: []string{"10.0.0.1"},
				},
			},
			true,
		),
		Entry("should reject GlobalNetworkSet with reserved labels",
			api.GlobalNetworkSet{
				ObjectMeta: v1.ObjectMeta{
					Name: "testset",
					Labels: map[string]string{
						"projectcalico.org/namespace": "foo",
					},
				},
				Spec: api.GlobalNetworkSetSpec{
					Nets: []string{"10.0.0.1"},
				},
			},
			false,
		),
		Entry("should reject GlobalNetworkSet with bad name",
			api.GlobalNetworkSet{
				ObjectMeta: v1.ObjectMeta{
					Name: "test$set",
				},
				Spec: api.GlobalNetworkSetSpec{
					Nets: []string{"10.0.0.1"},
				},
			},
			false,
		),

		Entry("should accept a valid BGP logging level: Info", api.BGPConfigurationSpec{LogSeverityScreen: "Info"}, true),
		Entry("should reject an invalid BGP logging level: info", api.BGPConfigurationSpec{LogSeverityScreen: "info"}, false),
		Entry("should reject an invalid BGP logging level: INFO", api.BGPConfigurationSpec{LogSeverityScreen: "INFO"}, false),
		Entry("should reject an invalid BGP logging level: invalidLvl", api.BGPConfigurationSpec{LogSeverityScreen: "invalidLvl"}, false),

		// (API) IP version.
		Entry("should accept IP version 4", api.Rule{Action: "Allow", IPVersion: &V4}, true),
		Entry("should accept IP version 6", api.Rule{Action: "Allow", IPVersion: &V6}, true),
		Entry("should reject IP version 0", api.Rule{Action: "Allow", IPVersion: &V0}, false),

		// (API) ProtoPort.
		Entry("should accept ProtoPort.Protocol: UDP", api.ProtoPort{Protocol: "UDP", Port: 0}, true),
		Entry("should accept ProtoPort.Protocol: TCP", api.ProtoPort{Protocol: "TCP", Port: 20}, true),
		Entry("should reject random ProtoPort.Protocol", api.ProtoPort{Protocol: "jolly-UDP", Port: 0}, false),

		// (API) Selectors.  Selectors themselves are thoroughly UT'd so only need to test simple
		// accept and reject cases here.
		Entry("should accept valid selector", api.EntityRule{Selector: "foo == \"bar\""}, true),
		Entry("should accept valid selector with 'has' and a '/'", api.EntityRule{Selector: "has(calico/k8s_ns)"}, true),
		Entry("should accept valid selector with 'has' and two '/'", api.EntityRule{Selector: "has(calico/k8s_ns/role)"}, true),
		Entry("should accept valid selector with 'has' and two '/' and '-.'", api.EntityRule{Selector: "has(calico/k8s_NS-.1/role)"}, true),
		Entry("should reject invalid selector", api.EntityRule{Selector: "thing=hello &"}, false),

		// (API) Labels and Annotations.
		Entry("should accept a valid labelsToApply", api.ProfileSpec{LabelsToApply: map[string]string{"project.calico.org/my-valid-label": value63}}, true),
		Entry("should reject an excessively long value in labelsToApply", api.ProfileSpec{LabelsToApply: map[string]string{"project.calico.org/my-valid-label": value64}}, false),
		Entry("should reject . at start of key in a labelsToApply", api.ProfileSpec{LabelsToApply: map[string]string{".mylabel": "value"}}, false),
		Entry("should reject ! in a labelsToApply", api.ProfileSpec{LabelsToApply: map[string]string{"my!nvalid-label": "value"}}, false),
		Entry("should reject $ in a labelsToApply", api.ProfileSpec{LabelsToApply: map[string]string{"my-invalid-label$": "value"}}, false),
		Entry("should accept valid labels in metadata",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Labels: map[string]string{
						"projectcalico.org/label": value63,
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, true,
		),
		// 64 bytes for a label value is too long.
		Entry("should reject an excessively long value in labels in metadata",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Labels: map[string]string{
						"projectcalico.org/label": value64,
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, false,
		),
		Entry("should reject invalid labels in metadata (uppercase domain)",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Labels: map[string]string{
						"ProjectCalico.org/label": "value",
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, false,
		),
		Entry("should accept valid labels in metadata (uppercase name)",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Labels: map[string]string{
						"projectcalico.org/Label": "value",
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, true,
		),
		Entry("should reject invalid annotations in metadata",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Annotations: map[string]string{
						"projectcalico.org$label": "value",
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, false,
		),
		Entry("should accept valid annotations in metadata (uppercase domain and name)",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Annotations: map[string]string{
						"ProjectCalico.org/Label": "value",
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, true,
		),
		Entry("should reject invalid annotations in metadata",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Annotations: map[string]string{
						"projectcalico.org$label": "value",
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, false,
		),
		Entry("should allow annotations in metadata <= 256k",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Annotations: map[string]string{
						"key": string(longValue[:maxAnnotationsLength-3]),
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, true,
		),
		Entry("should disallow annotations in metadata > 256k",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
					Annotations: map[string]string{
						"key": string(longValue[:maxAnnotationsLength-2]),
					},
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, false,
		),
		Entry("should allow a name of 253 chars",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: string(longValue[:maxNameLength]),
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, true,
		),
		Entry("should disallow a name of 254 chars",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: string(longValue[:maxNameLength+1]),
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, false,
		),

		// (API) Interface.
		Entry("should accept a valid interface", api.WorkloadEndpointSpec{InterfaceName: "Valid_Iface.0-9"}, true),
		Entry("should reject an interface that is too long", api.WorkloadEndpointSpec{InterfaceName: "interfaceTooLong"}, false),
		Entry("should reject & in an interface", api.WorkloadEndpointSpec{InterfaceName: "Invalid&Intface"}, false),
		Entry("should reject # in an interface", api.WorkloadEndpointSpec{InterfaceName: "Invalid#Intface"}, false),
		Entry("should reject : in an interface", api.WorkloadEndpointSpec{InterfaceName: "Invalid:Intface"}, false),

		// (API) FelixConfiguration.
		Entry("should accept a valid DefaultEndpointToHostAction value", api.FelixConfigurationSpec{DefaultEndpointToHostAction: "Drop"}, true),
		Entry("should reject an invalid DefaultEndpointToHostAction value 'drop' (lower case)", api.FelixConfigurationSpec{DefaultEndpointToHostAction: "drop"}, false),
		Entry("should accept a valid IptablesFilterAllowAction value 'Accept'", api.FelixConfigurationSpec{IptablesFilterAllowAction: "Accept"}, true),
		Entry("should accept a valid IptablesMangleAllowAction value 'Return'", api.FelixConfigurationSpec{IptablesMangleAllowAction: "Return"}, true),
		Entry("should reject an invalid IptablesMangleAllowAction value 'Drop'", api.FelixConfigurationSpec{IptablesMangleAllowAction: "Drop"}, false),
		Entry("should accept a valid KubeNodePortRanges value", api.FelixConfigurationSpec{KubeNodePortRanges: &[]numorstring.Port{
			mustParsePortRange(3000, 4000), mustParsePortRange(5000, 6000),
			mustParsePortRange(7000, 8000), mustParsePortRange(8000, 9000),
			mustParsePortRange(10000, 11000), mustParsePortRange(12000, 13000),
			numorstring.SinglePort(15000),
		}}, true),
		Entry("should reject a too-long KubeNodePortRanges value", api.FelixConfigurationSpec{KubeNodePortRanges: &[]numorstring.Port{
			mustParsePortRange(3000, 4000), mustParsePortRange(5000, 6000),
			mustParsePortRange(7000, 8000), mustParsePortRange(8000, 9000),
			mustParsePortRange(10000, 11000), mustParsePortRange(12000, 13000),
			mustParsePortRange(14000, 15000), mustParsePortRange(16000, 17000),
		}}, false),
		Entry("should reject a named port KubeNodePortRanges value", api.FelixConfigurationSpec{KubeNodePortRanges: &[]numorstring.Port{
			numorstring.NamedPort("testport"),
		}}, false),
		Entry("should accept a valid list of ExternalNodesCIDRList", api.FelixConfigurationSpec{ExternalNodesCIDRList: &[]string{"1.1.1.1", "1.1.1.2/32", "1.1.3.0/23"}},
			true),
		Entry("should reject an invalid list of ExternalNodesCIDRList", api.FelixConfigurationSpec{ExternalNodesCIDRList: &[]string{"foobar", "1.1.1.1"}}, false),
		Entry("should reject IPv6 list of ExternalNodesCIDRList", api.FelixConfigurationSpec{ExternalNodesCIDRList: &[]string{"abcd::1", "abef::2/128"}}, false),

		Entry("should reject an invalid LogSeverityScreen value 'badVal'", api.FelixConfigurationSpec{LogSeverityScreen: "badVal"}, false),
		Entry("should reject an invalid LogSeverityFile value 'badVal'", api.FelixConfigurationSpec{LogSeverityFile: "badVal"}, false),
		Entry("should reject an invalid LogSeveritySys value 'badVal'", api.FelixConfigurationSpec{LogSeveritySys: "badVal"}, false),
		Entry("should reject an invalid LogSeveritySys value 'Critical'", api.FelixConfigurationSpec{LogSeveritySys: "Critical"}, false),
		Entry("should accept a valid LogSeverityScreen value 'Fatal'", api.FelixConfigurationSpec{LogSeverityScreen: "Fatal"}, true),
		Entry("should accept a valid LogSeverityScreen value 'Warning'", api.FelixConfigurationSpec{LogSeverityScreen: "Warning"}, true),
		Entry("should accept a valid LogSeverityFile value 'Debug'", api.FelixConfigurationSpec{LogSeverityFile: "Debug"}, true),
		Entry("should accept a valid LogSeveritySys value 'Info'", api.FelixConfigurationSpec{LogSeveritySys: "Info"}, true),

		// (API) Protocol
		Entry("should accept protocol TCP", protocolFromString("TCP"), true),
		Entry("should accept protocol UDP", protocolFromString("UDP"), true),
		Entry("should accept protocol ICMP", protocolFromString("ICMP"), true),
		Entry("should accept protocol ICMPv6", protocolFromString("ICMPv6"), true),
		Entry("should accept protocol SCTP", protocolFromString("SCTP"), true),
		Entry("should accept protocol UDPLite", protocolFromString("UDPLite"), true),
		Entry("should accept protocol 1 as int", protocolFromInt(1), true),
		Entry("should accept protocol 255 as int", protocolFromInt(255), true),
		Entry("should accept protocol 255 as string", protocolFromString("255"), true),
		Entry("should accept protocol 1 as string", protocolFromString("1"), true),
		Entry("should reject protocol 0 as int", protocolFromInt(0), false),
		Entry("should reject protocol 256 as string", protocolFromString("256"), false),
		Entry("should reject protocol 0 as string", protocolFromString("0"), false),
		Entry("should reject protocol tcpfoo", protocolFromString("tcpfoo"), false),
		Entry("should reject protocol footcp", protocolFromString("footcp"), false),
		Entry("should reject protocol tcp", numorstring.Protocol{StrVal: "tcp", Type: numorstring.NumOrStringString}, false),

		// (API) IPNAT
		Entry("should accept valid IPNAT IPv4",
			api.IPNAT{
				InternalIP: ipv4_1,
				ExternalIP: ipv4_2,
			}, true),
		Entry("should accept valid IPNAT IPv6",
			api.IPNAT{
				InternalIP: ipv6_1,
				ExternalIP: ipv6_2,
			}, true),
		Entry("should reject IPNAT mixed IPv4 (int) and IPv6 (ext)",
			api.IPNAT{
				InternalIP: ipv4_1,
				ExternalIP: ipv6_1,
			}, false),
		Entry("should reject IPNAT mixed IPv6 (int) and IPv4 (ext)",
			api.IPNAT{
				InternalIP: ipv6_1,
				ExternalIP: ipv4_1,
			}, false),

		// (API) WorkloadEndpointSpec
		Entry("should accept workload endpoint with interface only",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
			}, true),
		Entry("should accept workload endpoint with networks and no nats",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1, netv4_2, netv6_1, netv6_2},
			}, true),
		Entry("should accept workload endpoint with IPv4 NAT covered by network",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1},
				IPNATs:        []api.IPNAT{{InternalIP: ipv4_1, ExternalIP: ipv4_2}},
			}, true),
		Entry("should accept workload endpoint with IPv6 NAT covered by network",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_1},
				IPNATs:        []api.IPNAT{{InternalIP: ipv6_1, ExternalIP: ipv6_2}},
			}, true),
		Entry("should accept workload endpoint with IPv4 and IPv6 NAT covered by network",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1, netv6_1},
				IPNATs: []api.IPNAT{
					{InternalIP: ipv4_1, ExternalIP: ipv4_2},
					{InternalIP: ipv6_1, ExternalIP: ipv6_2},
				},
			}, true),
		Entry("should accept workload endpoint with mixed-case ContainerID",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				ContainerID:   "Cath01234-G",
			}, true),
		Entry("should reject workload endpoint with no config", api.WorkloadEndpointSpec{}, false),
		Entry("should reject workload endpoint with IPv4 networks that contain >1 address",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_3},
			}, false),
		Entry("should reject workload endpoint with IPv6 networks that contain >1 address",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_3},
			}, false),
		Entry("should reject workload endpoint with nats and no networks",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNATs:        []api.IPNAT{{InternalIP: ipv4_2, ExternalIP: ipv4_1}},
			}, false),
		Entry("should reject workload endpoint with IPv4 NAT not covered by network",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1},
				IPNATs:        []api.IPNAT{{InternalIP: ipv4_2, ExternalIP: ipv4_1}},
			}, false),
		Entry("should reject workload endpoint with IPv6 NAT not covered by network",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_1},
				IPNATs:        []api.IPNAT{{InternalIP: ipv6_2, ExternalIP: ipv6_1}},
			}, false),
		Entry("should reject workload endpoint containerID that starts with a dash",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali0134",
				ContainerID:   "-abcdefg",
			}, false),
		Entry("should reject workload endpoint containerID that ends with a dash",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali0134",
				ContainerID:   "abcdeSg-",
			}, false),
		Entry("should reject workload endpoint containerID that contains a period",
			api.WorkloadEndpointSpec{
				InterfaceName: "cali0134",
				ContainerID:   "abcde-j.g",
			}, false),

		// (API) HostEndpointSpec
		Entry("should accept host endpoint with interface and node",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Node:          "node01",
			}, true),
		Entry("should accept host endpoint with expected IPs",
			api.HostEndpointSpec{
				ExpectedIPs: []string{ipv4_1, ipv6_1},
				Node:        "node01",
			}, true),
		Entry("should accept host endpoint with interface and expected IPs",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				ExpectedIPs:   []string{ipv4_1, ipv6_1},
				Node:          "node01",
			}, true),
		Entry("should reject host endpoint with no config", api.HostEndpointSpec{}, false),
		Entry("should reject host endpoint with blank interface an no IPs",
			api.HostEndpointSpec{
				InterfaceName: "",
				ExpectedIPs:   []string{},
				Node:          "node01",
			}, false),
		Entry("should accept host endpoint with prefixed profile name",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Profiles:      []string{"knp.default.fun", "knp.default.funner.11234-a"},
				Node:          "node01",
			}, true),
		Entry("should accept host endpoint without prefixed profile name",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Profiles:      []string{"fun-funner1234"},
				Node:          "node01",
			}, true),
		Entry("should reject host endpoint with no prefix and dots at the start of the name",
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				Profiles:      []string{".fun"},
				Node:          "node01",
			}, false),

		// (API) IPPool
		Entry("should accept IP pool with IPv4 CIDR /26",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{CIDR: netv4_3},
			}, true),
		Entry("should accept IP pool with IPv4 CIDR /10",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{CIDR: netv4_4},
			}, true),
		Entry("should accept IP pool with IPv6 CIDR /122",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:     netv6_3,
					IPIPMode: api.IPIPModeNever},
			}, true),
		Entry("should accept IP pool with IPv6 CIDR /10",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:     netv6_4,
					IPIPMode: api.IPIPModeNever},
			}, true),
		Entry("should accept a disabled IP pool with IPv4 CIDR /27",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:     netv4_5,
					Disabled: true},
			}, true),
		Entry("should accept a disabled IP pool with IPv6 CIDR /128",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:     netv6_1,
					IPIPMode: api.IPIPModeNever,
					Disabled: true},
			}, true),
		Entry("should reject IP pool with IPv4 CIDR /27", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: netv4_5}}, false),
		Entry("should reject IP pool with IPv6 CIDR /128", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: netv6_1}}, false),
		Entry("should reject IP pool with IPv4 CIDR /33", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "1.2.3.4/33"}}, false),
		Entry("should reject IP pool with IPv6 CIDR /129", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "aa:bb::/129"}}, false),
		Entry("should reject IPIPMode 'Always' for IPv6 pool",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:     netv6_1,
					IPIPMode: api.IPIPModeAlways},
			}, false),
		Entry("should reject IPv4 pool with a CIDR range overlapping with Link Local range",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "169.254.5.0/24"}}, false),
		Entry("should reject IPv6 pool with a CIDR range overlapping with Link Local range",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "fe80::/120"}}, false),

		// (API) IPIPMode
		Entry("should accept IPPool with no IPIP mode specified", api.IPPoolSpec{CIDR: "1.2.3.0/24"}, true),
		Entry("should accept IPIP mode Never (api)", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: api.IPIPModeNever}, true),
		Entry("should accept IPIP mode Never", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never"}, true),
		Entry("should accept IPIP mode Always", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Always"}, true),
		Entry("should accept IPIP mode CrossSubnet", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "CrossSubnet"}, true),
		Entry("should reject IPIP mode badVal", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "badVal"}, false),
		Entry("should reject IPIP mode never (lower case)", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "never"}, false),

		// (API) IPIP APIv1 backwards compatibility. Read-only field IPIP
		Entry("should accept a nil IPIP field", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never", IPIP: nil}, true),
		Entry("should accept it when the IPIP field is not specified", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never"}, true),
		Entry("should reject a non-nil IPIP field", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never", IPIP: &apiv1.IPIPConfiguration{Enabled: true, Mode: ipip.Always}}, false),

		// (API) NatOutgoing APIv1 backwards compatibility. Read-only field NatOutgoingV1
		Entry("should accept NATOutgoingV1 field set to true", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never", NATOutgoingV1: false}, true),
		Entry("should accept it when the NATOutgoingV1 field is not specified", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never"}, true),
		Entry("should reject NATOutgoingV1 field set to true", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never", NATOutgoingV1: true}, false),

		// (API) ICMPFields
		Entry("should accept ICMP with no config", api.ICMPFields{}, true),
		Entry("should accept ICMP with type with min value", api.ICMPFields{Type: &V0}, true),
		Entry("should accept ICMP with type with max value", api.ICMPFields{Type: &V254}, true),
		Entry("should accept ICMP with type and code with min value", api.ICMPFields{Type: &V128, Code: &V0}, true),
		Entry("should accept ICMP with type and code with min value", api.ICMPFields{Type: &V128, Code: &V255}, true),
		Entry("should reject ICMP with code and no type", api.ICMPFields{Code: &V0}, false),
		Entry("should reject ICMP with type too high", api.ICMPFields{Type: &V255}, false),
		Entry("should reject ICMP with code too high", api.ICMPFields{Type: &V128, Code: &V256}, false),

		// (API) Rule
		Entry("should accept Rule with protocol SCTP and no other config",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("SCTP"),
			}, true),
		Entry("should accept Rule with source ports and protocol type 6",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(6),
				Source: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
		Entry("should accept Rule with source named ports and protocol type 6",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(6),
				Source: api.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, true),
		Entry("should accept Rule with source named ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, true),
		Entry("should accept Rule with source named ports and protocol type udp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("UDP"),
				Source: api.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, true),
		Entry("should accept Rule with empty source ports and protocol type 7",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(7),
				Source: api.EntityRule{
					Ports: []numorstring.Port{},
				},
			}, true),
		Entry("should accept Rule with source !ports and protocol type 17",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(17),
				Source: api.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
		Entry("should accept Rule with empty source !ports and protocol type 100",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(100),
				Source: api.EntityRule{
					NotPorts: []numorstring.Port{},
				},
			}, true),
		Entry("should accept Rule with dest ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
		Entry("should reject Rule with dest ports and no protocol",
			api.Rule{
				Action: "Allow",
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with invalid port (port 0)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(0)},
				},
			}, false),
		Entry("should reject Rule with invalid port (name + number)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{{
						PortName: "foo",
						MinPort:  123,
						MaxPort:  456,
					}},
				},
			}, false),
		Entry("should reject named port Rule with invalid protocol",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("unknown"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			}, false),
		Entry("should accept Rule with empty dest ports and protocol type SCTP",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("SCTP"),
				Destination: api.EntityRule{
					Ports: []numorstring.Port{},
				},
			}, true),
		Entry("should accept Rule with empty dest !ports and protocol type ICMPv6",
			api.Rule{
				Action:    "Allow",
				IPVersion: &V6,
				Protocol:  protocolFromString("ICMPv6"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{},
				},
			}, true),
		Entry("should reject Rule with icmp fields and no protocol",
			api.Rule{
				Action:    "Allow",
				IPVersion: &V4,
				ICMP: &api.ICMPFields{
					Type: &V0,
				},
			}, false),
		Entry("should not reject Rule with icmp fields and no ipversion",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("ICMP"),
				ICMP: &api.ICMPFields{
					Type: &V0,
				},
			}, true),
		Entry("should not reject Rule with icmpv6 fields and no ipversion",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("ICMPv6"),
				ICMP: &api.ICMPFields{
					Type: &V0,
				},
			}, true),
		Entry("should reject Rule with mismatched ipversion for icmp",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("ICMP"),
				IPVersion: &V6,
			}, false),
		Entry("should reject Rule with mismatched ipversion for icmpv6",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("ICMPv6"),
				IPVersion: &V4,
			}, false),
		Entry("should allow Rule with correct ipversion for icmp",
			api.Rule{
				Action:    "Allow",
				IPVersion: &V4,
				Protocol:  protocolFromString("ICMP"),
				ICMP: &api.ICMPFields{
					Type: &V0,
				},
			}, true),
		Entry("should allow Rule with correct ipversion for icmpv6",
			api.Rule{
				Action:    "Allow",
				IPVersion: &V6,
				Protocol:  protocolFromString("ICMPv6"),
				ICMP: &api.ICMPFields{
					Type: &V0,
				},
			}, true),
		Entry("should reject Rule with source ports and protocol type 7",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(7),
				Source: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with source !ports and protocol type 100",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromInt(100),
				Source: api.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with dest ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("SCTP"),
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with dest !ports and protocol type udp",
			api.Rule{
				Action:    "Allow",
				IPVersion: &V4,
				Protocol:  protocolFromString("icmp"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, false),
		Entry("should reject Rule with invalid source ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					Ports: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with invalid source !ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					NotPorts: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with invalid dest ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					Ports: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with invalid dest !ports and protocol type tcp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{{MinPort: 200, MaxPort: 100}},
				},
			}, false),
		Entry("should reject Rule with one invalid port in the port range (MinPort 0)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Destination: api.EntityRule{
					NotPorts: []numorstring.Port{{MinPort: 0, MaxPort: 100}},
				},
			}, false),
		Entry("should reject rule mixed IPv4 (src) and IPv6 (dest)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					Nets: []string{netv4_3},
				},
				Destination: api.EntityRule{
					Nets: []string{netv6_3},
				},
			}, false),
		Entry("should reject rule mixed IPv6 (src) and IPv4 (dest)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					Nets: []string{netv6_2},
				},
				Destination: api.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("should reject rule mixed IPv6 version and IPv4 Net",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V6,
				Source: api.EntityRule{
					Nets: []string{netv4_4},
				},
				Destination: api.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("should reject rule mixed IPVersion and Source Net IP version",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V6,
				Source: api.EntityRule{
					Nets: []string{netv4_1},
				},
			}, false),
		Entry("should reject rule mixed IPVersion and Dest Net IP version",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V4,
				Destination: api.EntityRule{
					Nets: []string{netv6_1},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv4 (src) and IPv6 (dest)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					Nets: []string{netv4_3},
				},
				Destination: api.EntityRule{
					Nets: []string{netv6_3},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv6 (src) and IPv4 (dest)",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				Source: api.EntityRule{
					Nets: []string{netv6_2},
				},
				Destination: api.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv6 version and IPv4 Net",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V6,
				Source: api.EntityRule{
					Nets: []string{netv4_4},
				},
				Destination: api.EntityRule{
					Nets: []string{netv4_2},
				},
			}, false),
		Entry("net list: should reject rule mixed IPv6 version and IPv4 Net",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V6,
				Source: api.EntityRule{
					Nets: []string{netv4_4},
				},
				Destination: api.EntityRule{
					NotNets: []string{netv4_2},
				},
			}, false),
		Entry("net list: should reject rule mixed IPVersion and Source Net IP version",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V6,
				Source: api.EntityRule{
					Nets: []string{netv4_1},
				},
			}, false),
		Entry("net list: should reject rule mixed IPVersion and Dest Net IP version",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("TCP"),
				IPVersion: &V4,
				Destination: api.EntityRule{
					Nets: []string{netv6_1},
				},
			}, false),
		Entry("should reject rule with an IPv6 protocol and a IPVersion=4",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("ICMPv6"),
				IPVersion: &V4,
			}, false),
		Entry("should reject rule with an IPv4 protocol and a IPVersion=6",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("ICMP"),
				IPVersion: &V6,
			}, false),
		Entry("should accept Allow rule with HTTP clause",
			api.Rule{
				Action: "Allow",
				HTTP:   &api.HTTPMatch{Methods: []string{"GET"}},
			}, true),
		Entry("should reject Deny rule with HTTP clause",
			api.Rule{
				Action: "Deny",
				HTTP:   &api.HTTPMatch{Methods: []string{"GET"}},
			}, false),

		// (API) BGPPeerSpec
		Entry("should accept valid BGPPeerSpec", api.BGPPeerSpec{PeerIP: ipv4_1}, true),
		Entry("should reject invalid BGPPeerSpec (IPv4)", api.BGPPeerSpec{PeerIP: bad_ipv4_1}, false),
		Entry("should reject invalid BGPPeerSpec (IPv6)", api.BGPPeerSpec{PeerIP: bad_ipv6_1}, false),
		Entry("should reject BGPPeerSpec with both Node and NodeSelector", api.BGPPeerSpec{
			Node:         "my-node",
			NodeSelector: "has(mylabel)",
		}, false),
		Entry("should reject BGPPeerSpec with both PeerIP and PeerSelector", api.BGPPeerSpec{
			PeerIP:       ipv4_1,
			PeerSelector: "has(mylabel)",
		}, false),
		Entry("should reject BGPPeerSpec with both ASNumber and PeerSelector", api.BGPPeerSpec{
			ASNumber:     as61234,
			PeerSelector: "has(mylabel)",
		}, false),
		Entry("should accept BGPPeerSpec with NodeSelector and PeerSelector", api.BGPPeerSpec{
			NodeSelector: "has(mylabel)",
			PeerSelector: "has(mylabel)",
		}, true),

		// (API) NodeSpec
		Entry("should accept node with IPv4 BGP", api.NodeSpec{BGP: &api.NodeBGPSpec{IPv4Address: netv4_1}}, true),
		Entry("should accept node with IPv6 BGP", api.NodeSpec{BGP: &api.NodeBGPSpec{IPv6Address: netv6_1}}, true),
		Entry("should accept node with tunnel IP in BGP", api.NodeSpec{BGP: &api.NodeBGPSpec{IPv4IPIPTunnelAddr: "10.0.0.1"}}, true),
		Entry("should accept node with no BGP", api.NodeSpec{}, true),
		Entry("should reject node with an empty BGP", api.NodeSpec{BGP: &api.NodeBGPSpec{}}, false),
		Entry("should reject node with IPv6 address in IPv4 field", api.NodeSpec{BGP: &api.NodeBGPSpec{IPv4Address: netv6_1}}, false),
		Entry("should reject node with IPv4 address in IPv6 field", api.NodeSpec{BGP: &api.NodeBGPSpec{IPv6Address: netv4_1}}, false),

		// GlobalNetworkPolicy validation.
		Entry("disallow name with invalid character", &api.GlobalNetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "t~!s.h.i.ng"}}, false),
		Entry("disallow name with mixed case characters", &api.GlobalNetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "tHiNg"}}, false),
		Entry("allow valid name", &api.GlobalNetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "thing"}}, true),
		Entry("disallow k8s policy name", &api.GlobalNetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "knp.default.thing"}}, false),
		Entry("disallow name with dot", &api.GlobalNetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "t.h.i.ng"}}, false),
		Entry("should reject GlobalNetworkPolicy with both PreDNAT and DoNotTrack",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					DoNotTrack:     true,
					ApplyOnForward: true,
				},
			}, false,
		),
		Entry("should accept GlobalNetworkPolicy PreDNAT but not DoNotTrack",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
				},
			}, true,
		),
		Entry("should accept GlobalNetworkPolicy DoNotTrack but not PreDNAT",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        false,
					DoNotTrack:     true,
					ApplyOnForward: true,
				},
			}, true,
		),
		Entry("should reject pre-DNAT GlobalNetworkPolicy egress rules",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Egress:         []api.Rule{{Action: "Allow"}},
				},
			}, false,
		),
		Entry("should accept pre-DNAT GlobalNetworkPolicy ingress rules",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Ingress:        []api.Rule{{Action: "Allow"}},
				},
			}, true,
		),

		// GlobalNetworkPolicySpec ApplyOnForward field checks.
		Entry("should accept GlobalNetworkPolicy ApplyOnForward but not PreDNAT",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        false,
					ApplyOnForward: true,
				},
			}, true,
		),
		Entry("should accept GlobalNetworkPolicy ApplyOnForward but not DoNotTrack",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					DoNotTrack:     false,
					ApplyOnForward: true,
				},
			}, true,
		),
		Entry("should accept GlobalNetworkPolicy ApplyOnForward and PreDNAT",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
				},
			}, true,
		),
		Entry("should accept GlobalNetworkPolicy ApplyOnForward and DoNotTrack",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					DoNotTrack:     true,
					ApplyOnForward: true,
				},
			}, true,
		),
		Entry("should accept GlobalNetworkPolicy no ApplyOnForward DoNotTrack PreDNAT",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        false,
					DoNotTrack:     false,
					ApplyOnForward: false,
				},
			}, true,
		),
		Entry("should reject GlobalNetworkPolicy PreDNAT but not ApplyOnForward",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: false,
				},
			}, false,
		),
		Entry("should reject GlobalNetworkPolicy DoNotTrack but not ApplyOnForward",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					DoNotTrack:     true,
					ApplyOnForward: false,
				},
			}, false,
		),

		// GlobalNetworkPolicySpec Types field checks.
		Entry("allow missing Types",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec:       api.GlobalNetworkPolicySpec{},
			}, true,
		),
		Entry("allow empty Types",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Types: []api.PolicyType{},
				},
			}, true,
		),
		Entry("allow ingress Types",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("allow egress Types",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow ingress+egress Types",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("disallow repeated egress Types",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeEgress, api.PolicyTypeEgress},
				},
			}, false,
		),
		Entry("disallow unexpected value",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Types: []api.PolicyType{"unexpected"},
				},
			}, false,
		),

		Entry("allow Types without ingress when Ingress present (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{{Action: "Allow"}},
					Types:   []api.PolicyType{api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow Types without egress when Egress present (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow"}},
					Types:  []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("allow Types with ingress when Ingress present (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{{Action: "Allow"}},
					Types:   []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("allow Types with ingress+egress when Ingress present (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{{Action: "Allow"}},
					Types:   []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow Types with egress when Egress present (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow"}},
					Types:  []api.PolicyType{api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow Types with ingress+egress when Egress present (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow"}},
					Types:  []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow ingress Types with pre-DNAT (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Types:          []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("disallow egress Types with pre-DNAT (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Types:          []api.PolicyType{api.PolicyTypeEgress},
				},
			}, false,
		),
		Entry("disallow ingress+egress Types with pre-DNAT (gnp)",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Types:          []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, false,
		),
		Entry("disallow HTTP in egress rule",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow", HTTP: &api.HTTPMatch{Methods: []string{"GET"}}}},
					Types:  []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, false,
		),

		// NetworkPolicySpec Types field checks.
		Entry("allow valid name", &api.NetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "thing"}}, true),
		Entry("disallow name with dot", &api.NetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "t.h.i.ng"}}, false),
		Entry("disallow name with mixed case", &api.NetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "tHiNg"}}, false),
		Entry("allow valid name of 253 chars", &api.NetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: string(longValue[:maxNameLength])}}, true),
		Entry("disallow a name of 254 chars", &api.NetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: string(longValue[:maxNameLength+1])}}, false),
		Entry("allow k8s policy name", &api.NetworkPolicy{ObjectMeta: v1.ObjectMeta{Name: "knp.default.thing"}}, true),
		Entry("allow missing Types",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec:       api.NetworkPolicySpec{},
			}, true,
		),
		Entry("allow empty Types",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Types: []api.PolicyType{},
				},
			}, true,
		),
		Entry("allow ingress Types",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("allow egress Types",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow ingress+egress Types",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("disallow repeated egress Types",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Types: []api.PolicyType{api.PolicyTypeEgress, api.PolicyTypeEgress},
				},
			}, false,
		),
		Entry("disallow unexpected value",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Types: []api.PolicyType{"unexpected"},
				},
			}, false,
		),
		// In the initial implementation, we validated against the following two cases but we found
		// that prevented us from doing a smooth upgrade from type-less to typed policy since we
		// couldn't write a policy that would work for back-level Felix instances while also
		// specifying the type for up-level Felix instances.
		//
		// For NetworkPolicySpec
		Entry("allow Types without ingress when Ingress present",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{{Action: "Allow"}},
					Types:   []api.PolicyType{api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow Types without egress when Egress present",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow"}},
					Types:  []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("allow Types with ingress when Ingress present",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{{Action: "Allow"}},
					Types:   []api.PolicyType{api.PolicyTypeIngress},
				},
			}, true,
		),
		Entry("allow Types with ingress+egress when Ingress present",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{{Action: "Allow"}},
					Types:   []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow Types with egress when Egress present",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow"}},
					Types:  []api.PolicyType{api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("allow Types with ingress+egress when Egress present",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow"}},
					Types:  []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, true,
		),
		Entry("disallow HTTP in egress rule",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{{Action: "Allow", HTTP: &api.HTTPMatch{Methods: []string{"GET"}}}},
					Types:  []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
				},
			}, false,
		),
		Entry("allow HTTP Path with permitted match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{Exact: "/foo"}, {Prefix: "/bar"}}},
			true,
		),
		Entry("disallow HTTP Path with invalid match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{Exact: "/foo", Prefix: "/bar"}, {Prefix: "/bar"}}},
			false,
		),
		Entry("disallow HTTP Path with invalid match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{Exact: "/fo?o"}}},
			false,
		),
		Entry("disallow HTTP Path with invalid match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{Exact: "/fo o"}}},
			false,
		),
		Entry("disallow HTTP Path with invalid match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{Exact: "/f#oo"}}},
			false,
		),
		Entry("disallow HTTP Path with invalid match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{Exact: "/fo#!?o"}}},
			false,
		),
		Entry("disallow HTTP Path with empty match clauses",
			&api.HTTPMatch{Paths: []api.HTTPPath{{}}},
			false,
		),
		Entry("disallow HTTP Method with duplicate match clause",
			&api.HTTPMatch{Methods: []string{"GET", "GET", "Foo"}},
			false,
		),
	)
}

func protocolFromString(s string) *numorstring.Protocol {
	p := numorstring.ProtocolFromString(s)
	return &p
}

func protocolFromInt(i uint8) *numorstring.Protocol {
	p := numorstring.ProtocolFromInt(i)
	return &p
}

func mustParsePortRange(min, max uint16) numorstring.Port {
	p, err := numorstring.PortFromRange(min, max)
	if err != nil {
		panic(err)
	}
	return p
}
