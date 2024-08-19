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

package v3_test

import (
	"time"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

func init() {
	// We need some pointers to ints, so just define as values here.
	var Vneg1 = -1
	var V0 = 0
	var V4 = 4
	var V6 = 6
	var V128 = 128
	var V254 = 254
	var V255 = 255
	var V256 = 256
	var Vffffffff = 0xffffffff
	var V100000000 = 0x100000000

	// We need pointers to bools, so define the values here.
	var Vtrue = true
	var Vfalse = false

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
	peerv4_1 := "9.9.9.9:4444"
	peerv6_1 := "[aabb::ffff]:4444"

	bad_ipv4_1 := "999.999.999.999"
	bad_ipv6_1 := "xyz:::"

	protoTCP := numorstring.ProtocolFromString("TCP")
	protoUDP := numorstring.ProtocolFromString("UDP")
	protoSCTP := numorstring.ProtocolFromString("SCTP")
	protoNumeric := numorstring.ProtocolFromInt(123)

	as61234, _ := numorstring.ASNumberFromString("61234")

	validWireguardPortOrRulePriority := 12345
	invalidWireguardPortOrRulePriority := 99999

	var awsCheckEnable, awsCheckDisable, awsCheckDoNothing,
		awsCheckbadVal, awsCheckenable api.AWSSrcDstCheckOption

	awsCheckEnable = api.AWSSrcDstCheckOptionEnable
	awsCheckDisable = api.AWSSrcDstCheckOptionDisable
	awsCheckDoNothing = api.AWSSrcDstCheckOptionDoNothing
	awsCheckbadVal = api.AWSSrcDstCheckOption("badVal")
	awsCheckenable = api.AWSSrcDstCheckOption("enable")

	var bpfHostNetworkedNatEnabled, bpfHostNetworkedNatDisabled,
		bpfHostNetworkedNatenabled, bpfHostNetworkedNatBadVal api.BPFHostNetworkedNATType
	var bpfConnectTimeLBTCP, bpfConnectTimeLBEnabled,
		bpfConnectTimeLBDisabled, bpfConnectTimeLBBadVal api.BPFConnectTimeLBType

	bpfHostNetworkedNatEnabled = api.BPFHostNetworkedNATEnabled
	bpfHostNetworkedNatDisabled = api.BPFHostNetworkedNATDisabled
	bpfHostNetworkedNatenabled = api.BPFHostNetworkedNATType("enabled")
	bpfHostNetworkedNatBadVal = api.BPFHostNetworkedNATType("badVal")
	bpfConnectTimeLBTCP = api.BPFConnectTimeLBTCP
	bpfConnectTimeLBEnabled = api.BPFConnectTimeLBEnabled
	bpfConnectTimeLBDisabled = api.BPFConnectTimeLBDisabled
	bpfConnectTimeLBBadVal = api.BPFConnectTimeLBType("badVal")

	iptablesBackendLegacy := api.IptablesBackend(api.IptablesBackendLegacy)
	iptablesBackendNFTables := api.IptablesBackend(api.IptablesBackendNFTables)
	iptablesBackendAuto := api.IptablesBackend(api.IptablesBackendAuto)
	iptablesBackendbadVal := api.IptablesBackend("badVal")

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

	windowsManageFirewallRulesEnabled := api.WindowsManageFirewallRulesEnabled
	windowsManageFirewallRulesDisabled := api.WindowsManageFirewallRulesDisabled
	var windowsManageFirewallRulesBlah api.WindowsManageFirewallRulesMode = "blah"

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
		Entry("should accept EndpointPort with tcp protocol", libapiv3.WorkloadEndpointPort{
			Name:     "a-valid-port",
			Protocol: protoTCP,
			Port:     1234,
		}, true),
		Entry("should accept EndpointPort with udp protocol", libapiv3.WorkloadEndpointPort{
			Name:     "a-valid-port",
			Protocol: protoUDP,
			Port:     1234,
		}, true),
		Entry("should accept EndpointPort with sctp protocol", libapiv3.WorkloadEndpointPort{
			Name:     "a-valid-port",
			Protocol: protoSCTP,
			Port:     1234,
		}, true),
		Entry("should reject EndpointPort with empty name", libapiv3.WorkloadEndpointPort{
			Name:     "",
			Protocol: protoUDP,
			Port:     1234,
		}, false),
		Entry("should accept EndpointPort with empty name but HostPort specified", libapiv3.WorkloadEndpointPort{
			Name:     "",
			Protocol: protoUDP,
			Port:     1234,
			HostPort: 2345,
		}, true),
		Entry("should reject EndpointPort with no protocol", libapiv3.WorkloadEndpointPort{
			Name: "a-valid-port",
			Port: 1234,
		}, false),
		Entry("should reject EndpointPort with numeric protocol", libapiv3.WorkloadEndpointPort{
			Name:     "a-valid-port",
			Protocol: protoNumeric,
			Port:     1234,
		}, false),
		Entry("should reject EndpointPort with no port", libapiv3.WorkloadEndpointPort{
			Name:     "a-valid-port",
			Protocol: protoTCP,
		}, false),

		// (API) WorkloadEndpointSpec.
		Entry("should accept WorkloadEndpointSpec with a port (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []libapiv3.WorkloadEndpointPort{
					{
						Name:     "a-valid-port",
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			true,
		),
		Entry("should reject WorkloadEndpointSpec with an unnamed port and no host mapping (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []libapiv3.WorkloadEndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
					},
				},
			},
			false,
		),
		Entry("should accept WorkloadEndpointSpec with name-clashing ports (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []libapiv3.WorkloadEndpointPort{
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
		Entry("should accept WorkloadEndpointSpec with an unnamed port and a host port (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []libapiv3.WorkloadEndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
						HostPort: 2345,
					},
				},
			},
			true,
		),
		Entry("should reject WorkloadEndpointSpec with a port with an invalid host IP (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "eth0",
				Ports: []libapiv3.WorkloadEndpointPort{
					{
						Protocol: protoTCP,
						Port:     1234,
						HostPort: 2345,
						HostIP:   bad_ipv4_1,
					},
				},
			},
			false,
		),
		Entry("should reject WorkloadEndpointSpec with an invalid source spoofing config (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName:              "eth0",
				AllowSpoofedSourcePrefixes: []string{"10.abcd"},
			},
			false,
		),
		Entry("should accept WorkloadEndpointSpec with an ip or prefix in the source spoofing config (m)",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName:              "eth0",
				AllowSpoofedSourcePrefixes: []string{"10.0.0.1", "192.168.0.0/16"},
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
		Entry("should accept HostEndpointSpec with interfaceName *",
			api.HostEndpointSpec{
				InterfaceName: "*",
				Node:          "node01",
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
		Entry("should accept NetworkSetSpec with CIDRs and IPs",
			api.NetworkSetSpec{
				Nets: []string{
					"10.0.0.1",
					"11.0.0.0/8",
					"dead:beef::",
					"dead:beef::/96",
				},
			},
			true,
		),
		Entry("should reject NetworkSetSpec with bad CIDR",
			api.NetworkSetSpec{
				Nets: []string{
					"garbage",
				},
			},
			false,
		),
		Entry("should accept NetworkSet with labels",
			api.NetworkSet{
				ObjectMeta: v1.ObjectMeta{
					Name: "testset",
					Labels: map[string]string{
						"a": "b",
					},
				},
				Spec: api.NetworkSetSpec{
					Nets: []string{"10.0.0.1"},
				},
			},
			true,
		),
		Entry("should reject NetworkSet with reserved labels",
			api.NetworkSet{
				ObjectMeta: v1.ObjectMeta{
					Name: "testset",
					Labels: map[string]string{
						"projectcalico.org/namespace": "foo",
					},
				},
				Spec: api.NetworkSetSpec{
					Nets: []string{"10.0.0.1"},
				},
			},
			false,
		),
		Entry("should reject NetworkSet with bad name",
			api.NetworkSet{
				ObjectMeta: v1.ObjectMeta{
					Name: "test$set",
				},
				Spec: api.NetworkSetSpec{
					Nets: []string{"10.0.0.1"},
				},
			},
			false,
		),

		Entry("should accept a valid BGP logging level: Info", api.BGPConfigurationSpec{LogSeverityScreen: "Info"}, true),
		Entry("should reject an invalid BGP logging level: info", api.BGPConfigurationSpec{LogSeverityScreen: "info"}, false),
		Entry("should reject an invalid BGP logging level: INFO", api.BGPConfigurationSpec{LogSeverityScreen: "INFO"}, false),
		Entry("should reject an invalid BGP logging level: invalidLvl", api.BGPConfigurationSpec{LogSeverityScreen: "invalidLvl"}, false),
		Entry("should accept a valid BGP clusterIPs: 1.2.3.4", api.BGPConfigurationSpec{ServiceClusterIPs: []api.ServiceClusterIPBlock{{CIDR: "1.2.3.4"}}}, true),
		Entry("should accept a valid BGP externalIPs: 8.8.8.8", api.BGPConfigurationSpec{ServiceExternalIPs: []api.ServiceExternalIPBlock{{CIDR: "8.8.8.8"}}}, true),
		Entry("should reject invalid BGP clusterIPs: x.x.x.x", api.BGPConfigurationSpec{ServiceClusterIPs: []api.ServiceClusterIPBlock{{CIDR: "x.x.x.x"}}}, false),
		Entry("should reject invalid BGP externalIPs: x.x.x.x", api.BGPConfigurationSpec{ServiceExternalIPs: []api.ServiceExternalIPBlock{{CIDR: "y.y.y.y"}}}, false),
		Entry("should accept valid IPv6 BGP clusterIP", api.BGPConfigurationSpec{ServiceClusterIPs: []api.ServiceClusterIPBlock{{CIDR: "fdf5:1234::102:304"}}}, true),
		Entry("should accept valid IPv6 BGP externalIP", api.BGPConfigurationSpec{ServiceExternalIPs: []api.ServiceExternalIPBlock{{CIDR: "fdf5:1234::808:808"}}}, true),
		Entry("should accept a node mesh BGP password if node to node mesh is enabled",
			api.BGPConfigurationSpec{
				NodeToNodeMeshEnabled: &Vtrue,
				NodeMeshPassword: &api.BGPPassword{
					SecretKeyRef: &k8sv1.SecretKeySelector{
						LocalObjectReference: k8sv1.LocalObjectReference{
							Name: "test-secret",
						},
						Key: "bgp-password",
					},
				},
			}, true,
		),
		Entry("should reject a node mesh BGP password if node to node mesh is disabled",
			api.BGPConfigurationSpec{
				NodeToNodeMeshEnabled: &Vfalse,
				NodeMeshPassword: &api.BGPPassword{
					SecretKeyRef: &k8sv1.SecretKeySelector{
						LocalObjectReference: k8sv1.LocalObjectReference{
							Name: "test-secret",
						},
						Key: "bgp-password",
					},
				},
			}, false,
		),
		Entry("should accept a node mesh max restart time if node to node mesh is enabled",
			api.BGPConfigurationSpec{
				NodeToNodeMeshEnabled:  &Vtrue,
				NodeMeshMaxRestartTime: &v1.Duration{Duration: 200 * time.Second},
			}, true,
		),
		Entry("should reject a node mesh max restart time if node to node mesh is disabled",
			api.BGPConfigurationSpec{
				NodeToNodeMeshEnabled:  &Vfalse,
				NodeMeshMaxRestartTime: &v1.Duration{Duration: 200 * time.Second},
			}, false,
		),
		Entry("should accept valid interface names",
			api.BGPConfigurationSpec{
				IgnoredInterfaces: []string{"valid_iface*", "interface_name"},
			}, true,
		),
		Entry("should reject invalid interface name", api.BGPConfigurationSpec{IgnoredInterfaces: []string{"*"}}, false),

		// (API) IP version.
		Entry("should accept IP version 4", api.Rule{Action: "Allow", IPVersion: &V4}, true),
		Entry("should accept IP version 6", api.Rule{Action: "Allow", IPVersion: &V6}, true),
		Entry("should reject IP version 0", api.Rule{Action: "Allow", IPVersion: &V0}, false),

		// (API) ProtoPort.
		Entry("should accept ProtoPort.Protocol: UDP", api.ProtoPort{Protocol: "UDP", Port: 0}, true),
		Entry("should accept ProtoPort.Protocol: TCP", api.ProtoPort{Protocol: "TCP", Port: 20}, true),
		Entry("should accept ProtoPort.Protocol: SCTP", api.ProtoPort{Protocol: "SCTP", Port: 20}, true),
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
		Entry("should allow a valid nodeSelector",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3, NodeSelector: `foo == "bar"`},
			}, true,
		),
		Entry("should disallow a invalid nodeSelector",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "pool.name",
				},
				Spec: api.IPPoolSpec{CIDR: netv4_3, NodeSelector: "this is not valid selector syntax"},
			}, false,
		),

		// (API) Interface.
		Entry("should accept a valid interface", libapiv3.WorkloadEndpointSpec{InterfaceName: "Valid_Iface.0-9"}, true),
		Entry("should reject an interface that is too long", libapiv3.WorkloadEndpointSpec{InterfaceName: "interfaceTooLong"}, false),
		Entry("should reject & in an interface", libapiv3.WorkloadEndpointSpec{InterfaceName: "Invalid&Intface"}, false),
		Entry("should reject # in an interface", libapiv3.WorkloadEndpointSpec{InterfaceName: "Invalid#Intface"}, false),
		Entry("should reject : in an interface", libapiv3.WorkloadEndpointSpec{InterfaceName: "Invalid:Intface"}, false),

		// (API) FelixConfiguration.
		Entry("should accept a valid IptablesBackend value 'Legacy'", api.FelixConfigurationSpec{IptablesBackend: &iptablesBackendLegacy}, true),
		Entry("should accept a valid IptablesBackend value 'NFT'", api.FelixConfigurationSpec{IptablesBackend: &iptablesBackendNFTables}, true),
		Entry("should accept a valid IptablesBackend value 'Auto'", api.FelixConfigurationSpec{IptablesBackend: &iptablesBackendAuto}, true),
		Entry("should reject an invalid IptablesBackend value 'badVal'", api.FelixConfigurationSpec{IptablesBackend: &iptablesBackendbadVal}, false),
		Entry("should accept a valid DefaultEndpointToHostAction value", api.FelixConfigurationSpec{DefaultEndpointToHostAction: "Drop"}, true),
		Entry("should reject an invalid DefaultEndpointToHostAction value 'drop' (lower case)", api.FelixConfigurationSpec{DefaultEndpointToHostAction: "drop"}, false),
		Entry("should accept a valid IptablesFilterAllowAction value 'Accept'", api.FelixConfigurationSpec{IptablesFilterAllowAction: "Accept"}, true),
		Entry("should accept a valid IptablesMangleAllowAction value 'Return'", api.FelixConfigurationSpec{IptablesMangleAllowAction: "Return"}, true),
		Entry("should reject an invalid IptablesMangleAllowAction value 'Drop'", api.FelixConfigurationSpec{IptablesMangleAllowAction: "Drop"}, false),
		Entry("should accept a valid IptablesFilterDenyAction value 'Drop'", api.FelixConfigurationSpec{IptablesFilterDenyAction: "Drop"}, true),
		Entry("should accept a valid IptablesFilterDenyAction value 'Reject'", api.FelixConfigurationSpec{IptablesFilterDenyAction: "Reject"}, true),
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

		Entry("should accept aan empty OpenStackRegion", api.FelixConfigurationSpec{OpenstackRegion: ""}, true),
		Entry("should accept a valid OpenStackRegion", api.FelixConfigurationSpec{OpenstackRegion: "foo"}, true),
		Entry("should reject an invalid OpenStackRegion", api.FelixConfigurationSpec{OpenstackRegion: "FOO"}, false),
		Entry("should reject an overlong OpenStackRegion", api.FelixConfigurationSpec{OpenstackRegion: "my-region-has-a-very-long-and-extremely-interesting-name"}, false),

		Entry("should reject an invalid LogSeverityScreen value 'badVal'", api.FelixConfigurationSpec{LogSeverityScreen: "badVal"}, false),
		Entry("should reject an invalid LogSeverityFile value 'badVal'", api.FelixConfigurationSpec{LogSeverityFile: "badVal"}, false),
		Entry("should reject an invalid LogSeveritySys value 'badVal'", api.FelixConfigurationSpec{LogSeveritySys: "badVal"}, false),
		Entry("should reject an invalid LogSeveritySys value 'Critical'", api.FelixConfigurationSpec{LogSeveritySys: "Critical"}, false),
		Entry("should accept a valid LogSeverityScreen value 'Fatal'", api.FelixConfigurationSpec{LogSeverityScreen: "Fatal"}, true),
		Entry("should accept a valid LogSeverityScreen value 'Warning'", api.FelixConfigurationSpec{LogSeverityScreen: "Warning"}, true),
		Entry("should accept a valid LogSeverityFile value 'Debug'", api.FelixConfigurationSpec{LogSeverityFile: "Debug"}, true),
		Entry("should accept a valid LogSeveritySys value 'Info'", api.FelixConfigurationSpec{LogSeveritySys: "Info"}, true),

		Entry("should accept a valid IptablesNATOutgoingInterfaceFilter value 'cali-123'", api.FelixConfigurationSpec{IptablesNATOutgoingInterfaceFilter: "cali-123"}, true),
		Entry("should reject an invalid IptablesNATOutgoingInterfaceFilter value 'cali@123'", api.FelixConfigurationSpec{IptablesNATOutgoingInterfaceFilter: "cali@123"}, false),

		Entry("should reject an invalid BPFLogLevel value 'badVal'", api.FelixConfigurationSpec{BPFLogLevel: "badVal"}, false),
		Entry("should accept a valid BPFLogLevel value 'Info'", api.FelixConfigurationSpec{BPFLogLevel: "Info"}, true),
		Entry("should accept a valid BPFLogLevel value 'Debug'", api.FelixConfigurationSpec{BPFLogLevel: "Debug"}, true),
		Entry("should accept a valid BPFLogLevel value 'Off'", api.FelixConfigurationSpec{BPFLogLevel: "Off"}, true),

		Entry("should reject a valid BPFExternalServiceMode value 'Foo'", api.FelixConfigurationSpec{BPFExternalServiceMode: "Foo"}, false),
		Entry("should accept a valid BPFExternalServiceMode value 'Tunnel'", api.FelixConfigurationSpec{BPFExternalServiceMode: "Tunnel"}, true),
		Entry("should accept a valid BPFExternalServiceMode value 'DSR'", api.FelixConfigurationSpec{BPFExternalServiceMode: "DSR"}, true),

		Entry("should reject a negative BPFExtToServiceConnmark value", api.FelixConfigurationSpec{BPFExtToServiceConnmark: &Vneg1}, false),
		Entry("should reject a gte 32bit BPFExtToServiceConnmark value", api.FelixConfigurationSpec{BPFExtToServiceConnmark: &V100000000}, false),
		Entry("should accept a zero BPFExtToServiceConnmark value", api.FelixConfigurationSpec{BPFExtToServiceConnmark: &V0}, true),
		Entry("should accept a 0xffffffff BPFExtToServiceConnmark value", api.FelixConfigurationSpec{BPFExtToServiceConnmark: &Vffffffff}, true),

		Entry("should reject an invalid BPFDataIfacePattern value '*'", api.FelixConfigurationSpec{BPFDataIfacePattern: "*"}, false),
		Entry("should accept a valid BPFDataIfacePattern value 'eth.*'", api.FelixConfigurationSpec{BPFDataIfacePattern: "eth.*"}, true),

		Entry("should accept valid route table range", api.FelixConfigurationSpec{RouteTableRange: &api.RouteTableRange{Min: 1, Max: 250}}, true),
		Entry("should reject route table range min too small", api.FelixConfigurationSpec{RouteTableRange: &api.RouteTableRange{Min: 0, Max: 250}}, false),
		Entry("should reject route table range min negative", api.FelixConfigurationSpec{RouteTableRange: &api.RouteTableRange{Min: -5, Max: 250}}, false),
		Entry("should reject route table range max < min", api.FelixConfigurationSpec{RouteTableRange: &api.RouteTableRange{Min: 50, Max: 45}}, false),
		Entry("should reject route table range max too large", api.FelixConfigurationSpec{RouteTableRange: &api.RouteTableRange{Min: 1, Max: 253}}, false),
		Entry("should accept route table range with min == max", api.FelixConfigurationSpec{RouteTableRange: &api.RouteTableRange{Min: 8, Max: 8}}, true),

		Entry("should accept valid route table ranges", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 1, Max: 10000}}}, true),
		Entry("should accept route table ranges with min == max", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 8, Max: 8}}}, true),
		Entry("should accept multiple route table ranges with min == max", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 8, Max: 8}, {Min: 7, Max: 7}}}, true),
		Entry("should reject route table ranges min too small", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 0, Max: 250}}}, false),
		Entry("should reject route table ranges min negative", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: -5, Max: 250}}}, false),
		Entry("should reject route table ranges max < min", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 50, Max: 45}}}, false),
		Entry("should reject route table ranges max too large", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 1, Max: 0xf00000000}}}, false),
		Entry("should reject single route table ranges targeting too many tables", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 1, Max: 0x10000}}}, false),
		Entry("should reject multiple route table ranges targeting too many tables", api.FelixConfigurationSpec{RouteTableRanges: &api.RouteTableRanges{{Min: 1, Max: 2}, {Min: 3, Max: 4}, {Min: 5, Max: 0x10000}}}, false),

		Entry("should reject spec with both RouteTableRanges and RouteTableRange set", api.FelixConfigurationSpec{
			RouteTableRanges: &api.RouteTableRanges{
				{Min: 1, Max: 250},
			},
			RouteTableRange: &api.RouteTableRange{
				Min: 1, Max: 250,
			},
		}, false),

		Entry("should reject an invalid MTUIfacePattern value '*'", api.FelixConfigurationSpec{MTUIfacePattern: "*"}, false),
		Entry("should accept a valid MTUIfacePattern value 'eth.*'", api.FelixConfigurationSpec{MTUIfacePattern: "eth.*"}, true),

		Entry("should allow HealthTimeoutOverride 0", api.FelixConfigurationSpec{HealthTimeoutOverrides: []api.HealthTimeoutOverride{{Name: "Valid", Timeout: metav1.Duration{Duration: 0}}}}, true),
		Entry("should reject HealthTimeoutOverride -1", api.FelixConfigurationSpec{HealthTimeoutOverrides: []api.HealthTimeoutOverride{{Name: "Valid", Timeout: metav1.Duration{Duration: -1}}}}, false),
		Entry("should reject HealthTimeoutOverride with bad name", api.FelixConfigurationSpec{HealthTimeoutOverrides: []api.HealthTimeoutOverride{{Name: "%", Timeout: metav1.Duration{Duration: 10}}}}, false),
		Entry("should reject HealthTimeoutOverride with no name", api.FelixConfigurationSpec{HealthTimeoutOverrides: []api.HealthTimeoutOverride{{Name: "", Timeout: metav1.Duration{Duration: 10}}}}, false),

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
			libapiv3.IPNAT{
				InternalIP: ipv4_1,
				ExternalIP: ipv4_2,
			}, true),
		Entry("should accept valid IPNAT IPv6",
			libapiv3.IPNAT{
				InternalIP: ipv6_1,
				ExternalIP: ipv6_2,
			}, true),
		Entry("should reject IPNAT mixed IPv4 (int) and IPv6 (ext)",
			libapiv3.IPNAT{
				InternalIP: ipv4_1,
				ExternalIP: ipv6_1,
			}, false),
		Entry("should reject IPNAT mixed IPv6 (int) and IPv4 (ext)",
			libapiv3.IPNAT{
				InternalIP: ipv6_1,
				ExternalIP: ipv4_1,
			}, false),

		// (API) WorkloadEndpointSpec
		Entry("should accept workload endpoint with interface only",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
			}, true),
		Entry("should accept workload endpoint with networks and no nats",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1, netv4_2, netv6_1, netv6_2},
			}, true),
		Entry("should accept workload endpoint with IPv4 NAT covered by network",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1},
				IPNATs:        []libapiv3.IPNAT{{InternalIP: ipv4_1, ExternalIP: ipv4_2}},
			}, true),
		Entry("should accept workload endpoint with IPv6 NAT covered by network",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_1},
				IPNATs:        []libapiv3.IPNAT{{InternalIP: ipv6_1, ExternalIP: ipv6_2}},
			}, true),
		Entry("should accept workload endpoint with IPv4 and IPv6 NAT covered by network",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1, netv6_1},
				IPNATs: []libapiv3.IPNAT{
					{InternalIP: ipv4_1, ExternalIP: ipv4_2},
					{InternalIP: ipv6_1, ExternalIP: ipv6_2},
				},
			}, true),
		Entry("should accept workload endpoint with mixed-case ContainerID",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				ContainerID:   "Cath01234-G",
			}, true),
		Entry("should reject workload endpoint with no config", libapiv3.WorkloadEndpointSpec{}, false),
		Entry("should reject workload endpoint with IPv4 networks that contain >1 address",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_3},
			}, false),
		Entry("should reject workload endpoint with IPv6 networks that contain >1 address",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_3},
			}, false),
		Entry("should reject workload endpoint with nats and no networks",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNATs:        []libapiv3.IPNAT{{InternalIP: ipv4_2, ExternalIP: ipv4_1}},
			}, false),
		Entry("should reject workload endpoint with IPv4 NAT not covered by network",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv4_1},
				IPNATs:        []libapiv3.IPNAT{{InternalIP: ipv4_2, ExternalIP: ipv4_1}},
			}, false),
		Entry("should reject workload endpoint with IPv6 NAT not covered by network",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali012371237",
				IPNetworks:    []string{netv6_1},
				IPNATs:        []libapiv3.IPNAT{{InternalIP: ipv6_2, ExternalIP: ipv6_1}},
			}, false),
		Entry("should reject workload endpoint containerID that starts with a dash",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali0134",
				ContainerID:   "-abcdefg",
			}, false),
		Entry("should reject workload endpoint containerID that ends with a dash",
			libapiv3.WorkloadEndpointSpec{
				InterfaceName: "cali0134",
				ContainerID:   "abcdeSg-",
			}, false),
		Entry("should reject workload endpoint containerID that contains a period",
			libapiv3.WorkloadEndpointSpec{
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
					CIDR:      netv6_3,
					IPIPMode:  api.IPIPModeNever,
					VXLANMode: api.VXLANModeNever,
				},
			}, true),
		Entry("should accept IP pool with IPv6 CIDR /10",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:      netv6_4,
					IPIPMode:  api.IPIPModeNever,
					VXLANMode: api.VXLANModeNever,
				},
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
					CIDR:      netv6_1,
					IPIPMode:  api.IPIPModeNever,
					VXLANMode: api.VXLANModeNever,
					Disabled:  true},
			}, true),
		Entry("should reject IP pool with IPv4 CIDR /27", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: netv4_5}}, false),
		Entry("should reject IP pool with IPv6 CIDR /128", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: netv6_1}}, false),
		Entry("should reject IP pool with IPv4 CIDR /33", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "1.2.3.4/33"}}, false),
		Entry("should reject IP pool with IPv6 CIDR /129", api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "aa:bb::/129"}}, false),
		Entry("should reject IPIPMode 'Always' for IPv6 pool",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:      netv6_1,
					IPIPMode:  api.IPIPModeAlways,
					VXLANMode: api.VXLANModeNever,
				},
			}, false),
		Entry("should reject VXLANMode 'Always' for IPv6 pool",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR:      netv6_1,
					VXLANMode: api.VXLANModeAlways,
					IPIPMode:  api.IPIPModeNever,
				},
			}, false),
		Entry("should reject IPv4 pool with a CIDR range overlapping with Link Local range",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "169.254.5.0/24"}}, false),
		Entry("should reject IPv6 pool with a CIDR range overlapping with Link Local range",
			api.IPPool{ObjectMeta: v1.ObjectMeta{Name: "pool.name"}, Spec: api.IPPoolSpec{CIDR: "fe80::/120"}}, false),

		Entry("should accept IP pool with valid allowed uses",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR: netv4_4,
					AllowedUses: []api.IPPoolAllowedUse{
						api.IPPoolAllowedUseWorkload,
						api.IPPoolAllowedUseTunnel,
					},
				},
			}, true),
		Entry("should reject IP pool with invalid allowed uses",
			api.IPPool{
				ObjectMeta: v1.ObjectMeta{Name: "pool.name"},
				Spec: api.IPPoolSpec{
					CIDR: netv4_4,
					AllowedUses: []api.IPPoolAllowedUse{
						"Garbage",
					},
				},
			}, false),

		// (API) IPReservation
		Entry("should accept IPReservation with an IP",
			api.IPReservation{
				ObjectMeta: v1.ObjectMeta{Name: "ip-reservation.name"},
				Spec: api.IPReservationSpec{
					ReservedCIDRs: []string{"10.0.0.1"},
				},
			}, true),
		Entry("should accept IPReservation with a CIDR",
			api.IPReservation{
				ObjectMeta: v1.ObjectMeta{Name: "ip-reservation.name"},
				Spec: api.IPReservationSpec{
					ReservedCIDRs: []string{"10.0.1.0/24"},
				},
			}, true),
		Entry("should accept IPReservation IP and a CIDR",
			api.IPReservation{
				ObjectMeta: v1.ObjectMeta{Name: "ip-reservation.name"},
				Spec: api.IPReservationSpec{
					ReservedCIDRs: []string{"10.0.1.0/24", "192.168.0.34"},
				},
			}, true),
		Entry("should reject IPReservation with bad CIDR",
			api.IPReservation{
				ObjectMeta: v1.ObjectMeta{Name: "ip-reservation.name"},
				Spec: api.IPReservationSpec{
					ReservedCIDRs: []string{"garbage"},
				},
			}, false),
		Entry("should reject IPReservation with too-long CIDR",
			api.IPReservation{
				ObjectMeta: v1.ObjectMeta{Name: "ip-reservation.name"},
				Spec: api.IPReservationSpec{
					ReservedCIDRs: []string{"10.0.1.0/33"},
				},
			}, false),
		Entry("should accept IPReservation with an IPv6",
			api.IPReservation{
				ObjectMeta: v1.ObjectMeta{Name: "ip-reservation.name"},
				Spec: api.IPReservationSpec{
					ReservedCIDRs: []string{"10.0.0.1", "cafe::1", "cafe:f00d::/96"},
				},
			}, true),

		// (API) IPIPMode
		Entry("should accept IPPool with no IPIP mode specified", api.IPPoolSpec{CIDR: "1.2.3.0/24"}, true),
		Entry("should accept IPIP mode Never (api)", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: api.IPIPModeNever, VXLANMode: api.VXLANModeNever}, true),
		Entry("should accept IPIP mode Never", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never"}, true),
		Entry("should accept IPIP mode Always", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Always"}, true),
		Entry("should accept IPIP mode CrossSubnet", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "CrossSubnet"}, true),
		Entry("should reject IPIP mode badVal", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "badVal"}, false),
		Entry("should reject IPIP mode never (lower case)", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "never"}, false),

		// (API) VXLANMode
		Entry("should reject IPIP mode and VXLAN mode", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Always", VXLANMode: "Always"}, false),
		Entry("should accept VXLAN mode Always", api.IPPoolSpec{CIDR: "1.2.3.0/24", VXLANMode: "Always"}, true),
		Entry("should accept VXLAN mode CrossSubnet", api.IPPoolSpec{CIDR: "1.2.3.0/24", VXLANMode: api.VXLANModeCrossSubnet}, true),
		Entry("should accept VXLAN mode Never ", api.IPPoolSpec{CIDR: "1.2.3.0/24", VXLANMode: "Never"}, true),
		Entry("should reject VXLAN mode never", api.IPPoolSpec{CIDR: "1.2.3.0/24", VXLANMode: "never"}, false),
		Entry("should reject VXLAN mode badVal", api.IPPoolSpec{CIDR: "1.2.3.0/24", VXLANMode: "badVal"}, false),

		// (API) IPIP APIv1 backwards compatibility. Read-only field IPIP
		Entry("should accept a nil IPIP field", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never", IPIP: nil}, true),
		Entry("should accept it when the IPIP field is not specified", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never"}, true),
		Entry("should reject a non-nil IPIP field", api.IPPoolSpec{CIDR: "1.2.3.0/24", IPIPMode: "Never", IPIP: &api.IPIPConfiguration{Enabled: true, Mode: encap.Always}}, false),

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
		Entry("should allow Rule with dest ports and protocol type sctp",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("SCTP"),
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(1)},
				},
			}, true),
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
		Entry("should reject rule with an IPv6 protocol and an IPVersion=4",
			api.Rule{
				Action:    "Allow",
				Protocol:  protocolFromString("ICMPv6"),
				IPVersion: &V4,
			}, false),
		Entry("should reject rule with an IPv4 protocol and an IPVersion=6",
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
		Entry("should reject non-TCP protocol with HTTP clause",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("UDP"),
				HTTP:     &api.HTTPMatch{Methods: []string{"GET"}},
			}, false),
		Entry("should accept TCP protocol with HTTP clause",
			api.Rule{
				Action:   "Allow",
				Protocol: protocolFromString("TCP"),
				HTTP:     &api.HTTPMatch{Methods: []string{"GET"}},
			}, true),
		Entry("should accept missing protocol with HTTP clause",
			api.Rule{
				Action: "Allow",
				HTTP:   &api.HTTPMatch{Methods: []string{"GET"}},
			}, true),
		Entry("should accept Rule with valid annotations",
			api.Rule{
				Action:   "Allow",
				Metadata: &api.RuleMetadata{Annotations: map[string]string{"foo": "bar"}},
			}, true),
		Entry("should reject Rule with invalid annotations",
			api.Rule{
				Action:   "Allow",
				Metadata: &api.RuleMetadata{Annotations: map[string]string{"...": "bar"}},
			}, false),

		// (API) BGPFilterSpec
		Entry("should reject invalid BGPFilter rule-v4 interface - 1", api.BGPFilterRuleV4{
			Interface: "eth&",
			Action:    "Reject",
		}, false),
		Entry("should reject invalid BGPFilter rule-v4 interface - 2", api.BGPFilterRuleV4{
			Interface: "%face",
			Action:    "Reject",
		}, false),
		Entry("should reject invalid BGPFilter rule-v4 interface - 3", api.BGPFilterRuleV4{
			Interface: "\"ace",
			Action:    "Reject",
		}, false),
		Entry("should reject invalid BGPFilter rule-v6 interface - 1", api.BGPFilterRuleV6{
			Interface: "$cali",
			Action:    "Reject",
		}, false),
		Entry("should reject invalid BGPFilter rule-v6 interface - 2", api.BGPFilterRuleV6{
			Interface: "eth#",
			Action:    "Reject",
		}, false),
		Entry("should reject invalid BGPFilter rule-v6 interface - 3", api.BGPFilterRuleV6{
			Interface: "\"face",
			Action:    "Reject",
		}, false),
		Entry("should accept valid BGPFilter rule-v4 interface - 1 ", api.BGPFilterRuleV4{
			Interface:     "ethx",
			Source:        "RemotePeers",
			CIDR:          "192.168.0.0/26",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept valid BGPFilter rule-v4 interface - 2", api.BGPFilterRuleV4{
			Interface:     "*.calico",
			CIDR:          "192.168.0.0/26",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept valid BGPFilter rule-v4 interface - 3", api.BGPFilterRuleV4{
			Interface: "eth*",
			Source:    "RemotePeers",
			Action:    "Accept",
		}, true),
		Entry("should accept valid BGPFilter rule-v6 interface - 1", api.BGPFilterRuleV6{
			Interface:     "ethx",
			Source:        "RemotePeers",
			CIDR:          "ffee::/64",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept valid BGPFilter rule-v6 interface - 2", api.BGPFilterRuleV6{
			Interface:     "*.calico",
			CIDR:          "ee2::dddd/128",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept valid BGPFilter rule-v6 interface - 3", api.BGPFilterRuleV6{
			Interface: "*.calico",
			Source:    "RemotePeers",
			Action:    "Accept",
		}, true),
		Entry("should accept BGPFilter with only rule-v4 interface - 1 ", api.BGPFilterRuleV4{
			Interface: "ethx",
			Action:    "Accept",
		}, true),
		Entry("should accept BGPFilter with only rule-v4 interface - 2", api.BGPFilterRuleV4{
			Interface: "eth*",
			Action:    "Accept",
		}, true),
		Entry("should accept BGPFilter with only rule-v6 interface - 1", api.BGPFilterRuleV6{
			Interface: "ethx.",
			Action:    "Accept",
		}, true),
		Entry("should accept BGPFilter with only rule-v6 interface - 2", api.BGPFilterRuleV6{
			Interface: "*.calico",
			Action:    "Accept",
		}, true),
		Entry("should reject invalid BGPFilter rule-v4 source", api.BGPFilterRuleV4{
			Source: "xyz",
			Action: "Reject",
		}, false),
		Entry("should reject invalid BGPFilter rule-v6 source", api.BGPFilterRuleV6{
			Source: "xyz",
			Action: "Reject",
		}, false),
		Entry("should accept valid BGPFilter rule-v4 source", api.BGPFilterRuleV4{
			Source:        "RemotePeers",
			CIDR:          "192.168.0.0/26",
			MatchOperator: "In",
			Action:        "Reject",
		}, true),
		Entry("should accept valid BGPFilter rule-v6 source", api.BGPFilterRuleV6{
			Source:        "RemotePeers",
			CIDR:          "ffee::/64",
			MatchOperator: "In",
			Action:        "Reject",
		}, true),
		Entry("should accept BGPFilter rule with only source set - 1", api.BGPFilterRuleV4{
			Source: "RemotePeers",
			Action: "Reject",
		}, true),
		Entry("should accept BGPFilter rule with only source set - 2", api.BGPFilterRuleV6{
			Source: "RemotePeers",
			Action: "Reject",
		}, true),
		Entry("should accept BGPFilter rule with valid IPv4 CIDR", api.BGPFilterRuleV4{
			CIDR:          "192.168.0.0/26",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with valid IPv6 CIDR", api.BGPFilterRuleV6{
			CIDR:          "ffee::/64",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should reject BGPFilter rule with invalid IPv4 CIDR - 1 ", api.BGPFilterRuleV4{
			CIDR:          "x.x.x.x/26",
			MatchOperator: "In",
			Action:        "Accept",
		}, false),
		Entry("should reject BGPFilter rule with invalid IPv4 CIDR - 2", api.BGPFilterRuleV4{
			CIDR:          "ffee::/64",
			MatchOperator: "In",
			Action:        "Accept",
		}, false),
		Entry("should reject BGPFilter rule with invalid IPv6 CIDR - 1", api.BGPFilterRuleV6{
			CIDR:          "xxxx::/64",
			MatchOperator: "In",
			Action:        "Accept",
		}, false),
		Entry("should reject BGPFilter rule with invalid IPv6 CIDR - 2", api.BGPFilterRuleV6{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "In",
			Action:        "Accept",
		}, false),
		Entry("should reject BGPFilter rule with invalid operator - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "fancyOperator",
			Action:        "Accept",
		}, false),
		Entry("should reject BGPFilter rule with invalid operator - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "fancyOperator",
			Action:        "Accept",
		}, false),
		Entry("should accept BGPFilter rule with In operator - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with In operator - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "In",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with NotIn operator - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "NotIn",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with NotIn operator - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "NotIn",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with Equal operator - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "Equal",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with Equal operator - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "Equal",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with NotEqual operator - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "NotEqual",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with NotEqual operator - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "NotEqual",
			Action:        "Accept",
		}, true),
		Entry("should reject BGPFilter rule with no CIDR when MatchOperator is set - 1", api.BGPFilterRuleV4{
			MatchOperator: "NotEqual",
			Action:        "Reject",
		}, false),
		Entry("should reject BGPFilter rule with no CIDR when MatchOperator is set - 2", api.BGPFilterRuleV6{
			MatchOperator: "NotEqual",
			Action:        "Reject",
		}, false),
		Entry("should reject BGPFilter rule with no MatchOperator when CIDR is set - 1", api.BGPFilterRuleV4{
			CIDR:   "10.0.10.0/32",
			Action: "Reject",
		}, false),
		Entry("should reject BGPFilter rule with no MatchOperator when CIDR is set - 2", api.BGPFilterRuleV6{
			CIDR:   "ffff::/128",
			Action: "Reject",
		}, false),
		Entry("should reject BGPFilter rule with invalid Action - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "NotEqual",
			Action:        "ActionX",
		}, false),
		Entry("should reject BGPFilter rule with invalid action - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "NotEqual",
			Action:        "ActionX",
		}, false),
		Entry("should accept BGPFilter rule with Accept action - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "NotEqual",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with Accept action - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "NotEqual",
			Action:        "Accept",
		}, true),
		Entry("should accept BGPFilter rule with Reject action - 1", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/32",
			MatchOperator: "NotEqual",
			Action:        "Reject",
		}, true),
		Entry("should accept BGPFilter rule with Reject action - 2", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "NotEqual",
			Action:        "Reject",
		}, true),
		Entry("should reject BGPFilter rule with no action - 1", api.BGPFilterRuleV4{
			MatchOperator: "NotEqual",
			CIDR:          "10.0.10.0/32",
		}, false),
		Entry("should reject BGPFilter rule with no action - 2", api.BGPFilterRuleV6{
			MatchOperator: "NotEqual",
			CIDR:          "ffff::/128",
		}, false),
		Entry("should accept BGPFilter rule with just an action - 1", api.BGPFilterRuleV4{
			Action: "Reject",
		}, true),
		Entry("should accept BGPFilter rule with just an action - 2", api.BGPFilterRuleV6{
			Action: "Reject",
		}, true),
		Entry("should accept BGPFilterV4 rule with PrefixLength Min set", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/24",
			MatchOperator: "In",
			Action:        "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV4{
				Min: int32Helper(25),
			},
		}, true),
		Entry("should accept BGPFilterV4 rule with PrefixLength Max set", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/24",
			MatchOperator: "In",
			Action:        "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV4{
				Max: int32Helper(30),
			},
		}, true),
		Entry("should reject BGPFilterV4 rule with PrefixLength Max is out-of-bounds", api.BGPFilterRuleV4{
			CIDR:          "10.0.10.0/24",
			MatchOperator: "In",
			Action:        "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV4{
				Max: int32Helper(64),
			},
		}, false),
		Entry("should reject BGPFilterV4 rule with PrefixLength populated and CIDR missing", api.BGPFilterRuleV4{
			Interface: "ethx.",
			Action:    "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV4{
				Min: int32Helper(16),
			},
		}, false),
		Entry("should accept BGPFilterV6 rule with PrefixLength Min set", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "In",
			Action:        "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV6{
				Min: int32Helper(65),
			},
		}, true),
		Entry("should accept BGPFilterV6 rule with PrefixLength Max set", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "In",
			Action:        "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV6{
				Max: int32Helper(96),
			},
		}, true),
		Entry("should reject BGPFilterV6 rule with PrefixLength Min is negative", api.BGPFilterRuleV6{
			CIDR:          "ffff::/128",
			MatchOperator: "In",
			Action:        "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV6{
				Min: int32Helper(-16),
			},
		}, false),
		Entry("should reject BGPFilterV6 rule with PrefixLength populated and CIDR missing", api.BGPFilterRuleV6{
			Interface: "*.calico",
			Action:    "Reject",
			PrefixLength: &api.BGPFilterPrefixLengthV6{
				Min: int32Helper(120),
			},
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
		Entry("should reject BGPPeer with ReachableBy but without PeerIP", api.BGPPeerSpec{
			ReachableBy: ipv4_2,
		}, false),
		Entry("should reject BGPPeer with ReachableBy (IPv6) but without PeerIP", api.BGPPeerSpec{
			ReachableBy: ipv6_2,
		}, false),
		Entry("should accept BGPPeer with ReachableBy and PeerIP", api.BGPPeerSpec{
			PeerIP:      peerv4_1,
			ReachableBy: ipv4_1,
		}, true),
		Entry("should accept BGPPeer with ReachableBy (IPv6) and PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP:      peerv6_1,
			ReachableBy: ipv6_1,
		}, true),
		Entry("should reject BGPPeer with invalid ReachableBy", api.BGPPeerSpec{
			PeerIP:      peerv4_1,
			ReachableBy: bad_ipv4_1,
		}, false),
		Entry("should reject BGPPeer with invalid ReachableBy (IPv6)", api.BGPPeerSpec{
			PeerIP:      peerv6_1,
			ReachableBy: bad_ipv6_1,
		}, false),
		Entry("should reject BGPPeer with mismatched family address of ReachableBy and PeerIP", api.BGPPeerSpec{
			PeerIP:      ipv4_1,
			ReachableBy: ipv6_1,
		}, false),
		Entry("should reject BGPPeer with mismatched family address of ReachableBy and PeerIP:Port", api.BGPPeerSpec{
			PeerIP:      peerv4_1,
			ReachableBy: ipv6_1,
		}, false),
		Entry("should reject BGPPeer with mismatched family address of ReachableBy and PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP:      ipv6_1,
			ReachableBy: ipv4_1,
		}, false),
		Entry("should reject BGPPeer with mismatched family address of ReachableBy and PeerIP:Port (IPv6)", api.BGPPeerSpec{
			PeerIP:      peerv6_1,
			ReachableBy: ipv4_1,
		}, false),
		Entry("should accept BGPPeerSpec with Password", api.BGPPeerSpec{
			PeerIP: ipv4_1,
			Password: &api.BGPPassword{
				SecretKeyRef: &k8sv1.SecretKeySelector{
					LocalObjectReference: k8sv1.LocalObjectReference{Name: "tigera-bgp-passwords"},
					Key:                  "my-peering",
				},
			},
		}, true),
		Entry("should reject invalid BGPPeerSpec (selector)", api.BGPPeerSpec{
			NodeSelector: "kubernetes.io/hostname: == 'casey-crc-kadm-node-4'",
		}, false),
		Entry("should accept BGPPeerSpec with port in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: "192.168.1.1:500",
		}, true),
		Entry("should accept BGPPeerSpec with port in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[9000::]:500",
		}, true),
		Entry("should reject BGPPeerSpec with invalid port in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: "[192.168.0.0]:98956",
		}, false),
		Entry("should reject BGPPeerSpec with invalid port in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: "192.168.0.0:65536",
		}, false),
		Entry("should reject BGPPeerSpec with invalid port in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: "192.168.0.0:0",
		}, false),
		Entry("should reject BGPPeerSpec with invalid IP in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: "192.168.0.330:170",
		}, false),
		Entry("should reject BGPPeerSpec with invalid port in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[9000::]:98956",
		}, false),
		Entry("should reject invalid BGPPeerSpec without port set in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: "192.168.0.0:",
		}, false),
		Entry("should reject invalid BGPPeerSpec without port set in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[9000::]:",
		}, false),
		Entry("should reject BGPPeerSpec with invalid port in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[9000::]:65536",
		}, false),
		Entry("should reject BGPPeerSpec with invalid port in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[9000::]:0",
		}, false),
		Entry("should reject BGPPeerSpec with invalid IP in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[9000::FFFFF]:170",
		}, false),
		Entry("should reject invalid BGPPeerSpec when port is set with empty IP in PeerIP (IPv4)", api.BGPPeerSpec{
			PeerIP: ":8552",
		}, false),
		Entry("should reject invalid BGPPeerSpec when port is set with empty IP in PeerIP (IPv6)", api.BGPPeerSpec{
			PeerIP: "[]:8552",
		}, false),

		// BGPPeer SourceAddress
		Entry("BGPPeer with valid SourceAddress UseNodeIP", api.BGPPeerSpec{
			SourceAddress: api.SourceAddressUseNodeIP,
		}, true),
		Entry("BGPPeer with valid SourceAddress None", api.BGPPeerSpec{
			SourceAddress: api.SourceAddressNone,
		}, true),
		Entry("BGPPeer with invalid SourceAddress", api.BGPPeerSpec{
			SourceAddress: api.SourceAddress("rubbish"),
		}, false),

		// BGPPeer MaxRestartTime
		Entry("BGPPeer with valid MaxRestartTime", api.BGPPeerSpec{
			MaxRestartTime: &v1.Duration{Duration: 10 * time.Second},
		}, true),

		// (API) NodeSpec
		Entry("should accept node with IPv4 BGP", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{IPv4Address: netv4_1}}, true),
		Entry("should accept node with IPv6 BGP", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{IPv6Address: netv6_1}}, true),
		Entry("should accept node with tunnel IP in BGP", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{IPv4IPIPTunnelAddr: "10.0.0.1"}}, true),
		Entry("should accept node with no BGP", libapiv3.NodeSpec{}, true),
		Entry("should reject node with an empty BGP", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{}}, false),
		Entry("should reject node with IPv6 address in IPv4 field", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{IPv4Address: netv6_1}}, false),
		Entry("should reject node with IPv4 address in IPv6 field", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{IPv6Address: netv4_1}}, false),
		Entry("should reject node with bad RR cluster ID #1", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{
			IPv4Address:             netv4_1,
			RouteReflectorClusterID: "abcdef",
		}}, false),
		Entry("should reject node with bad RR cluster ID #2", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{
			IPv4Address:             netv4_1,
			RouteReflectorClusterID: "300.34.3.1",
		}}, false),
		Entry("should accept node with good RR cluster ID", libapiv3.NodeSpec{BGP: &libapiv3.NodeBGPSpec{
			IPv4Address:             netv4_1,
			RouteReflectorClusterID: "245.0.0.1",
		}}, true),

		// Wireguard config field tests
		Entry("should allow valid Wireguard public-key", libapiv3.NodeStatus{
			WireguardPublicKey: "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=",
		}, true),
		Entry("should allow valid IP address on Wireguard config", libapiv3.NodeSpec{Wireguard: &libapiv3.NodeWireguardSpec{
			InterfaceIPv4Address: ipv4_1,
		}}, true),
		Entry("should reject invalid IP address on Wireguard config", libapiv3.NodeSpec{Wireguard: &libapiv3.NodeWireguardSpec{
			InterfaceIPv4Address: "foo.bar",
		}}, false),
		Entry("should reject invalid Wireguard public-key", libapiv3.NodeStatus{
			WireguardPublicKey: "foobar",
		}, false),

		// AWS source-destination-check.
		Entry("should accept a valid AWSSrcDstCheck value 'DoNothing'", api.FelixConfigurationSpec{AWSSrcDstCheck: &awsCheckDoNothing}, true),
		Entry("should accept a valid AWSSrcDstCheck value 'Enable'", api.FelixConfigurationSpec{AWSSrcDstCheck: &awsCheckEnable}, true),
		Entry("should accept a valid AWSSrcDstCheck value 'Disable'", api.FelixConfigurationSpec{AWSSrcDstCheck: &awsCheckDisable}, true),
		Entry("should reject an invalid AWSSrcDstCheck value 'enable'", api.FelixConfigurationSpec{AWSSrcDstCheck: &awsCheckenable}, false),
		Entry("should reject an invalid AWSSrcDstCheck value 'badVal'", api.FelixConfigurationSpec{AWSSrcDstCheck: &awsCheckbadVal}, false),

		// BPF CTLB config check
		Entry("should accept a valid BPFHostNetworkedNATWithoutCTLB value 'Disabled'", api.FelixConfigurationSpec{BPFHostNetworkedNATWithoutCTLB: &bpfHostNetworkedNatDisabled}, true),
		Entry("should accept a valid BPFHostNetworkedNATWithoutCTLB value 'Enabled'", api.FelixConfigurationSpec{BPFHostNetworkedNATWithoutCTLB: &bpfHostNetworkedNatEnabled}, true),
		Entry("should accept a valid BPFConnectTimeLoadBalancing value 'Enabled'", api.FelixConfigurationSpec{BPFConnectTimeLoadBalancing: &bpfConnectTimeLBEnabled}, true),
		Entry("should accept a valid BPFConnectTimeLoadBalancing value 'Disabled'", api.FelixConfigurationSpec{BPFConnectTimeLoadBalancing: &bpfConnectTimeLBDisabled}, true),
		Entry("should accept a valid BPFConnectTimeLoadBalancing value 'TCP'", api.FelixConfigurationSpec{BPFConnectTimeLoadBalancing: &bpfConnectTimeLBTCP}, true),
		Entry("should reject an invalid BPFHostNetworkedNATWithoutCTLB value 'enabled'", api.FelixConfigurationSpec{BPFHostNetworkedNATWithoutCTLB: &bpfHostNetworkedNatenabled}, false),
		Entry("should reject an invalid BPFHostNetworkedNATWithoutCTLB value 'BadVal'", api.FelixConfigurationSpec{BPFHostNetworkedNATWithoutCTLB: &bpfHostNetworkedNatBadVal}, false),
		Entry("should reject an invalid BPFConnectTimeLoadBalancing value 'BadVal'", api.FelixConfigurationSpec{BPFConnectTimeLoadBalancing: &bpfConnectTimeLBBadVal}, false),

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
		Entry("disallow global() in namespaceSelector field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					NamespaceSelector: "global()",
				},
			}, false,
		),
		Entry("disallow global() in selector field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Selector: "global()",
				},
			}, false,
		),
		Entry("disallow global() in serviceAccountSelector field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					ServiceAccountSelector: "global()",
				},
			}, false,
		),
		Entry("disallow global() in EntityRule selector field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "global()",
							},
						},
					},
				},
			}, false,
		),
		Entry("allow global() and projectcalico.org/name in EntityRule namespaceSelector field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								NamespaceSelector: "global()",
							},
							Destination: api.EntityRule{
								NamespaceSelector: "projectcalico.org/name == 'test'",
							},
						},
					},
				},
			}, true,
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
		Entry("disallow global() in selector field",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Selector: "global()",
				},
			}, false,
		),
		Entry("disallow global() in serviceAccountSelector field",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					ServiceAccountSelector: "global()",
				},
			}, false,
		),
		Entry("NetworkPolicy: disallow junk in PerformanceHints field",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					PerformanceHints: []api.PolicyPerformanceHint{"junk"},
				},
			}, false,
		),
		Entry("NetworkPolicy: allow PerfHintAssumeNeededOnEveryNode in PerformanceHints field",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					PerformanceHints: []api.PolicyPerformanceHint{api.PerfHintAssumeNeededOnEveryNode},
				},
			}, true,
		),
		Entry("NetworkPolicy: disallow dupes in PerformanceHints field",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					PerformanceHints: []api.PolicyPerformanceHint{
						api.PerfHintAssumeNeededOnEveryNode,
						api.PerfHintAssumeNeededOnEveryNode,
					},
				},
			}, false,
		),
		Entry("GlobalNetworkPolicy: disallow junk in PerformanceHints field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PerformanceHints: []api.PolicyPerformanceHint{"junk"},
				},
			}, false,
		),
		Entry("GlobalNetworkPolicy: allow PerfHintAssumeNeededOnEveryNode in PerformanceHints field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PerformanceHints: []api.PolicyPerformanceHint{api.PerfHintAssumeNeededOnEveryNode},
				},
			}, true,
		),
		Entry("GlobalNetworkPolicy: disallow dupes in PerformanceHints field",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					PerformanceHints: []api.PolicyPerformanceHint{
						api.PerfHintAssumeNeededOnEveryNode,
						api.PerfHintAssumeNeededOnEveryNode,
					},
				},
			}, false,
		),
		Entry("allow global() and projectcalico.org/name in EntityRule namespaceSelector field",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								NamespaceSelector: "global()",
							},
							Destination: api.EntityRule{
								NamespaceSelector: "projectcalico.org/name == 'test'",
							},
						},
					},
				},
			}, true,
		),
		Entry("allow a Service match in an egress rule destination",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, true,
		),
		Entry("disallow a Service match in an egress rule source",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("allow a Service match in an ingress rule source",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, true,
		),
		Entry("disallow a Service match in an ingress rule destination",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, true,
		),
		Entry("disallow a Service match AND a ServiceAccount match",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								ServiceAccounts: &api.ServiceAccountMatch{
									Names: []string{"serviceaccount"},
								},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a Ports match on an egress destination rule",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Ports: []numorstring.Port{
									{MinPort: 80, MaxPort: 80},
								},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a NotPorts match on an egress destination rule",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Egress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								NotPorts: []numorstring.Port{
									{MinPort: 80, MaxPort: 80},
								},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("allow a Service match AND a Ports match specified on the source on an ingress source rule",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action:   "Allow",
							Protocol: protocolFromString("TCP"),
							Source: api.EntityRule{
								Ports: []numorstring.Port{
									{MinPort: 80, MaxPort: 80},
								},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, true,
		),
		Entry("allow a Service match AND a NotPorts match on an ingress source rule",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action:   "Allow",
							Protocol: protocolFromString("TCP"),
							Source: api.EntityRule{
								NotPorts: []numorstring.Port{
									{MinPort: 80, MaxPort: 80},
								},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, true,
		),
		Entry("disallow a Service match AND a Nets match",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Nets: []string{"10.0.0.0/8"},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a NotNets match",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								NotNets: []string{"10.0.0.0/8"},
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a Selector match",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Selector: "x == 'y'",
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a NotSelector match",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								NotSelector: "x == 'y'",
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a NamespaceSelector match",
			&api.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.NetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								NamespaceSelector: "x == 'y'",
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("allow a Service match on a GNP",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match without a namespace on a GNP",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Egress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								Services: &api.ServiceMatch{
									Name: "service1",
								},
							},
						},
					},
				},
			}, false,
		),
		Entry("disallow a Service match AND a NamespaceSelector match on a GNP",
			&api.GlobalNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{Name: "thing"},
				Spec: api.GlobalNetworkPolicySpec{
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Destination: api.EntityRule{
								NamespaceSelector: "x == 'y'",
								Services: &api.ServiceMatch{
									Name:      "service1",
									Namespace: "default",
								},
							},
						},
					},
				},
			}, false,
		),

		// Validate EntityRule against special selectors global().
		// Extra spaces added in some cases to make sure validation handles it.
		Entry("disallow global() in EntityRule selector field",
			&api.EntityRule{
				Selector: "  global()  ",
			}, false,
		),
		Entry("allow global() in EntityRule namespaceSelector field",
			&api.EntityRule{
				NamespaceSelector: "  global()  ",
			}, true,
		),
		Entry("disallow global() in EntityRule namespaceSelector field AND'd with other expressions",
			&api.EntityRule{
				NamespaceSelector: " global() && all()",
			}, false,
		),
		Entry("disallow global() in EntityRule namespaceSelector field OR'd other expressions",
			&api.EntityRule{
				NamespaceSelector: "global()||all()",
			}, false,
		),
		Entry("disallow bad selectors in EntityRule selector field",
			&api.EntityRule{
				Selector: "global() && bad",
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
		Entry("should not accept an invalid IP address",
			api.FelixConfigurationSpec{NATOutgoingAddress: bad_ipv4_1}, false,
		),
		Entry("should not accept a masked IP",
			api.FelixConfigurationSpec{NATOutgoingAddress: netv4_1}, false,
		),
		Entry("should not accept an IPV6 address",
			api.FelixConfigurationSpec{NATOutgoingAddress: ipv6_1}, false,
		),
		Entry("should accept a valid IP address",
			api.FelixConfigurationSpec{NATOutgoingAddress: ipv4_1}, true,
		),
		Entry("should accept a valid prometheusMetricsHost value 'localhost'", api.FelixConfigurationSpec{PrometheusMetricsHost: "localhost"}, true),
		Entry("should accept a valid prometheusMetricsHost value '10.0.0.1'", api.FelixConfigurationSpec{PrometheusMetricsHost: "10.0.0.1"}, true),
		Entry("should accept a valid prometheusMetricsHost value 'fe80::ea7a:70fa:cf74:25d5'", api.FelixConfigurationSpec{PrometheusMetricsHost: "fe80::ea7a:70fa:cf74:25d5"}, true),
		Entry("should reject an invalid prometheusMetricsHost value 'localhost#'", api.FelixConfigurationSpec{PrometheusMetricsHost: "localhost#"}, false),
		Entry("should reject an invalid prometheusMetricsHost value '0: 1::1'", api.FelixConfigurationSpec{PrometheusMetricsHost: "0: 1::1"}, false),
		// Testcases for DeviceRouteSourceAddress address
		Entry("should accept a valid IPv4 address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddress: ipv4_1}, true,
		),
		Entry("should not accept a valid IPv6 address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddress: ipv6_1}, false,
		),
		Entry("should not accept an invalid IP address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddress: bad_ipv4_1}, false,
		),
		Entry("should not accept a masked IP address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddress: netv4_1}, false,
		),
		// Testcases for DeviceRouteSourceAddressIPv6 address
		Entry("should accept a valid IPv6 address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: ipv6_1}, true,
		),
		Entry("should not accept a valid IPv4 address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: ipv4_1}, false,
		),
		Entry("should not accept an invalid IPv4 address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: bad_ipv6_1}, false,
		),
		Entry("should not accept a masked IPv6 address",
			api.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: netv6_1}, false,
		),
		Entry("should accept a valid listening port",
			api.FelixConfigurationSpec{WireguardListeningPort: &validWireguardPortOrRulePriority}, true,
		),
		Entry("should reject a valid listening port",
			api.FelixConfigurationSpec{WireguardListeningPort: &invalidWireguardPortOrRulePriority}, false,
		),
		Entry("should accept a valid routing rule priority",
			api.FelixConfigurationSpec{WireguardRoutingRulePriority: &validWireguardPortOrRulePriority}, true,
		),
		Entry("should reject a valid routing rule priority",
			api.FelixConfigurationSpec{WireguardRoutingRulePriority: &invalidWireguardPortOrRulePriority}, false,
		),
		Entry("should accept valid Wireguard interface", api.FelixConfigurationSpec{WireguardInterfaceName: "wg0"}, true),
		Entry("should reject valid Wireguard interface", api.FelixConfigurationSpec{WireguardInterfaceName: "wg&0"}, false),

		// FelixConfigurationSpec.ServiceLoopPrevention
		Entry("should accept ServiceLoopPrevention Drop", api.FelixConfigurationSpec{ServiceLoopPrevention: "Drop"}, true),
		Entry("should accept ServiceLoopPrevention Reject", api.FelixConfigurationSpec{ServiceLoopPrevention: "Reject"}, true),
		Entry("should accept ServiceLoopPrevention Disabled", api.FelixConfigurationSpec{ServiceLoopPrevention: "Disabled"}, true),
		Entry("should reject ServiceLoopPrevention Wibbly", api.FelixConfigurationSpec{ServiceLoopPrevention: "Wibbly"}, false),

		Entry("should accept WindowsManageFirewallRules value Disabled", api.FelixConfigurationSpec{WindowsManageFirewallRules: &windowsManageFirewallRulesDisabled}, true),
		Entry("should accept WindowsManageFirewallRules value Enabled", api.FelixConfigurationSpec{WindowsManageFirewallRules: &windowsManageFirewallRulesEnabled}, true),
		Entry("should reject WindowsManageFirewallRules value blah", api.FelixConfigurationSpec{WindowsManageFirewallRules: &windowsManageFirewallRulesBlah}, false),

		// KubeControllersConfiguration validation
		Entry("should not accept invalid HealthChecks",
			api.KubeControllersConfigurationSpec{HealthChecks: "invalid"}, false,
		),
		Entry("should accept valid HealthChecks",
			api.KubeControllersConfigurationSpec{HealthChecks: "Enabled"}, true,
		),
		Entry("should not accept invalid log severity",
			api.KubeControllersConfigurationSpec{LogSeverityScreen: "invalid"}, false,
		),
		Entry("should accept valid log severity",
			api.KubeControllersConfigurationSpec{LogSeverityScreen: "Error"}, true,
		),
		Entry("should accept valid compaction period",
			api.KubeControllersConfigurationSpec{EtcdV3CompactionPeriod: &v1.Duration{Duration: time.Minute * 12}}, true,
		),
		Entry("should accept ControllersConfig with no values",
			api.KubeControllersConfigurationSpec{Controllers: api.ControllersConfig{}}, true,
		),
		Entry("should accept ControllersConfig with empty values",
			api.KubeControllersConfigurationSpec{Controllers: api.ControllersConfig{
				Node:             &api.NodeControllerConfig{},
				Policy:           &api.PolicyControllerConfig{},
				WorkloadEndpoint: &api.WorkloadEndpointControllerConfig{},
				ServiceAccount:   &api.ServiceAccountControllerConfig{},
				Namespace:        &api.NamespaceControllerConfig{},
			}}, true,
		),
		Entry("should accept valid reconciliation period on node",
			api.NodeControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 5}}, true,
		),
		Entry("should not accept invalid sync labels",
			api.NodeControllerConfig{SyncLabels: "yes"}, false,
		),
		Entry("should accept valid sync labels",
			api.NodeControllerConfig{SyncLabels: "Disabled"}, true,
		),
		Entry("should not accept invalid host endpoint auto create",
			api.NodeControllerConfig{HostEndpoint: &api.AutoHostEndpointConfig{AutoCreate: "Totally"}}, false,
		),
		Entry("should accept valid host endpoint auto create",
			api.NodeControllerConfig{HostEndpoint: &api.AutoHostEndpointConfig{AutoCreate: "Enabled"}}, true,
		),
		Entry("should accept empty host endpoint auto create",
			api.NodeControllerConfig{HostEndpoint: &api.AutoHostEndpointConfig{}}, true,
		),
		Entry("should accept valid reconciliation period on policy",
			api.PolicyControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Second * 330}}, true,
		),
		Entry("should accept valid reconciliation period on workload endpoint",
			api.WorkloadEndpointControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Second * 330}}, true,
		),
		Entry("should accept valid reconciliation period on service account",
			api.ServiceAccountControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Second * 330}}, true,
		),
		Entry("should accept valid reconciliation period on namespace",
			api.NamespaceControllerConfig{ReconcilerPeriod: &v1.Duration{Duration: time.Second * 330}}, true,
		),

		// BGP Communities validation in BGPConfigurationSpec
		Entry("should not accept community when PrefixAdvertisement is empty", api.BGPConfigurationSpec{
			Communities: []api.Community{{Name: "community-test", Value: "101:5695"}},
		}, false),
		Entry("should not accept communities with value and without name", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Value: "536:785"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, false),
		Entry("should not accept communities with name and without value", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, false),
		Entry("should accept communities with name and standard BGP community value", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "100:520"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, true),
		Entry("should accept communities with name and large BGP community value", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "100:520:56"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, true),
		Entry("should not accept communities with name and invalid community value/format", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "100"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, false),
		Entry("should not accept communities with name and invalid community value/format", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "ab-n"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, false),
		Entry("should not accept communities with name and invalid standard community value(> 16 bit)", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "65536:999999"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, false),
		Entry("should not accept communities with name and invalid large community value(> 32 bit)", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "4147483647:999999"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:100"}}},
		}, false),
		Entry("should not accept communities without CIDR in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{Communities: []string{"100:5964"}}},
		}, false),
		Entry("should not accept CIDR without communities in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28"}},
		}, false),
		Entry("should accept IPv4 CIDR in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "192.168.10.0/28", Communities: []string{"100:5964:50"}}},
		}, true),
		Entry("should accept IPv6 CIDR in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"100:5964:50"}}},
		}, true),
		Entry("should accept standard BGP community value in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"100:5964", "200:594"}}},
		}, true),
		Entry("should accept large BGP community value in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"100:5964:1147483647"}}},
		}, true),
		Entry("should not accept invalid standard community value(> 16 bit) in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"100:1147483647"}}},
		}, false),
		Entry("should not accept invalid large community value(> 32 bit) in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"100:100:5147483647"}}},
		}, false),
		Entry("should accept combination of large and standard BGP community value in PrefixAdvertisement", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"100:5964:1147483647", "100:5223"}}},
		}, true),
		Entry("should not accept community name that is not defined", api.BGPConfigurationSpec{
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"nonexistent-community"}}},
		}, false),
		Entry("should accept community name whose values are defined", api.BGPConfigurationSpec{
			Communities:          []api.Community{{Name: "community-test", Value: "101:5695"}},
			PrefixAdvertisements: []api.PrefixAdvertisement{{CIDR: "2001:4860::/128", Communities: []string{"community-test", "8988:202"}}},
		}, true),

		// Block Affinities validation in BlockAffinitySpec
		Entry("should accept non-deleted block affinities", libapiv3.BlockAffinitySpec{
			Deleted: "false",
			State:   "confirmed",
			CIDR:    "10.0.0.0/24",
			Node:    "node-1",
		}, true),
		Entry("should not accept deleted block affinities", libapiv3.BlockAffinitySpec{
			Deleted: "true",
			State:   "confirmed",
			CIDR:    "10.0.0.0/24",
			Node:    "node-1",
		}, false),

		Entry("should accept a valid BPFForceTrackPacketsFromIfaces value 'docker+'", api.FelixConfigurationSpec{BPFForceTrackPacketsFromIfaces: &[]string{"docker+"}}, true),
		Entry("should accept a valid BPFForceTrackPacketsFromIfaces value 'docker0,docker1'", api.FelixConfigurationSpec{BPFForceTrackPacketsFromIfaces: &[]string{"docker0", "docker1"}}, true),
		Entry("should reject invalid BPFForceTrackPacketsFromIfaces value 'cali-123,cali@456'", api.FelixConfigurationSpec{BPFForceTrackPacketsFromIfaces: &[]string{"cali-123", "cali@456"}}, false),
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

func int32Helper(i int32) *int32 {
	return &i
}
