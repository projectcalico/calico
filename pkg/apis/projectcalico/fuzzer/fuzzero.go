// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
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
// limitations under the License.package fuzzer

package fuzzer

import (
	fuzz "github.com/google/gofuzz"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/projectcalico/apiserver/pkg/apis/projectcalico"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

func createSourceEntityRule() apiv3.EntityRule {
	port80 := numorstring.SinglePort(uint16(80))
	port443 := numorstring.SinglePort(uint16(443))

	return apiv3.EntityRule{
		Nets:        []string{"10.100.10.1/32"},
		Selector:    "mylabel = value1",
		Ports:       []numorstring.Port{port80},
		NotNets:     []string{"192.168.40.1/32"},
		NotSelector: "has(label1)",
		NotPorts:    []numorstring.Port{port443},
	}
}

func createDestinationEntityRule() apiv3.EntityRule {
	port80 := numorstring.SinglePort(uint16(80))
	port443 := numorstring.SinglePort(uint16(443))

	return apiv3.EntityRule{
		Nets:        []string{"10.100.1.1/32"},
		Selector:    "",
		Ports:       []numorstring.Port{port443},
		NotNets:     []string{"192.168.80.1/32"},
		NotSelector: "has(label2)",
		NotPorts:    []numorstring.Port{port80},
	}
}

// Funcs returns the fuzzer functions for the apps api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []interface{} {
	return []interface{}{
		func(s *projectcalico.HostEndpoint, c fuzz.Continue) {

			c.FuzzNoCustom(s) // fuzz first without calling this function again

			s.Spec.Ports = []apiv3.EndpointPort{
				{
					Name: "some-port",
					Protocol: numorstring.Protocol{
						Type:   numorstring.NumOrStringString,
						StrVal: numorstring.ProtocolTCP,
					},
					Port: 1234,
				},
				{
					Name: "another-port",
					Protocol: numorstring.Protocol{
						Type:   numorstring.NumOrStringString,
						StrVal: numorstring.ProtocolUDP,
					},
					Port: 5432,
				},
			}
		},
		func(s *projectcalico.FelixConfiguration, c fuzz.Continue) {

			c.FuzzNoCustom(s) // fuzz first without calling this function again

			s.Spec.NATPortRange = &numorstring.Port{MinPort: 32768, MaxPort: 65000, PortName: ""}
			s.Spec.ExternalNodesCIDRList = nil
			s.Spec.FailsafeInboundHostPorts = nil
			s.Spec.FailsafeOutboundHostPorts = nil
			s.Spec.KubeNodePortRanges = &[]numorstring.Port{
				{MinPort: 30000, MaxPort: 32767, PortName: ""},
			}

		},
		func(s *projectcalico.ClusterInformation, c fuzz.Continue) {

			c.FuzzNoCustom(s) // fuzz first without calling this function again

			s.Name = "default"
		},
		func(s *projectcalico.GlobalNetworkPolicy, c fuzz.Continue) {

			c.FuzzNoCustom(s) // fuzz first without calling this function again

			source := createSourceEntityRule()
			destination := createSourceEntityRule()

			s.Spec.Ingress = []apiv3.Rule{
				{Action: apiv3.Allow,
					Source:      source,
					Destination: destination,
				},
			}
			s.Spec.Egress = []apiv3.Rule{
				{Action: apiv3.Allow,
					Source:      source,
					Destination: destination,
				},
			}
		},
		func(s *projectcalico.NetworkPolicy, c fuzz.Continue) {

			c.FuzzNoCustom(s) // fuzz first without calling this function again

			source := createSourceEntityRule()
			destination := createSourceEntityRule()

			s.Spec.Ingress = []apiv3.Rule{
				{Action: apiv3.Allow,
					Source:      source,
					Destination: destination,
				},
			}
			s.Spec.Egress = []apiv3.Rule{
				{Action: apiv3.Allow,
					Source:      source,
					Destination: destination,
				},
			}
		},
		func(s *projectcalico.Profile, c fuzz.Continue) {

			c.FuzzNoCustom(s) // fuzz first without calling this function again

			v4 := 4
			itype := 1
			intype := 3
			icode := 4
			incode := 6
			iproto := numorstring.ProtocolFromString("TCP")
			inproto := numorstring.ProtocolFromString("UDP")
			port80 := numorstring.SinglePort(uint16(80))
			port443 := numorstring.SinglePort(uint16(443))
			irule := apiv3.Rule{
				Action:    apiv3.Allow,
				IPVersion: &v4,
				Protocol:  &iproto,
				ICMP: &apiv3.ICMPFields{
					Type: &itype,
					Code: &icode,
				},
				NotProtocol: &inproto,
				NotICMP: &apiv3.ICMPFields{
					Type: &intype,
					Code: &incode,
				},
				Source: apiv3.EntityRule{
					Nets:        []string{"10.100.10.1"},
					Selector:    "calico/k8s_ns == selector1",
					Ports:       []numorstring.Port{port80},
					NotNets:     []string{"192.168.40.1"},
					NotSelector: "has(label1)",
					NotPorts:    []numorstring.Port{port443},
				},
				Destination: apiv3.EntityRule{
					Nets:        []string{"10.100.1.1"},
					Selector:    "calico/k8s_ns == selector2",
					Ports:       []numorstring.Port{port443},
					NotNets:     []string{"192.168.80.1"},
					NotSelector: "has(label2)",
					NotPorts:    []numorstring.Port{port80},
				},
			}

			etype := 2
			entype := 7
			ecode := 5
			encode := 8
			eproto := numorstring.ProtocolFromInt(uint8(30))
			enproto := numorstring.ProtocolFromInt(uint8(62))
			erule := apiv3.Rule{
				Action:    apiv3.Allow,
				IPVersion: &v4,
				Protocol:  &eproto,
				ICMP: &apiv3.ICMPFields{
					Type: &etype,
					Code: &ecode,
				},
				NotProtocol: &enproto,
				NotICMP: &apiv3.ICMPFields{
					Type: &entype,
					Code: &encode,
				},
				Source: apiv3.EntityRule{
					Nets:        []string{"10.100.1.1"},
					Selector:    "calico/k8s_ns == selector2",
					Ports:       []numorstring.Port{port443},
					NotNets:     []string{"192.168.80.1"},
					NotSelector: "has(label2)",
					NotPorts:    []numorstring.Port{port80},
				},
				Destination: apiv3.EntityRule{
					Nets:        []string{"10.100.10.1"},
					Selector:    "calico/k8s_ns == selector1",
					Ports:       []numorstring.Port{port80},
					NotNets:     []string{"192.168.40.1"},
					NotSelector: "has(label1)",
					NotPorts:    []numorstring.Port{port443},
				},
			}

			s.Spec.Ingress = []apiv3.Rule{irule}
			s.Spec.Egress = []apiv3.Rule{erule}
		},
	}
}
