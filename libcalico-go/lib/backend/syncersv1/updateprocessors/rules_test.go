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

package updateprocessors_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the Rules Conversion Functions", func() {
	It("should handle the conversion of rules", func() {
		By("Creating and converting an inbound rule")
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
				Nets:        []string{"10.100.10.1/32"},
				Selector:    "mylabel = value1",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1/32"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.1.1/32"},
				Selector:    "",
				Ports:       []numorstring.Port{port443},
				NotNets:     []string{"192.168.80.1/32"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
			HTTP: &apiv3.HTTPMatch{
				Methods: []string{"GET", "PUT"},
				Paths:   []apiv3.HTTPPath{{Exact: "/bar"}, {Prefix: "/foo1"}},
			},
			Metadata: &apiv3.RuleMetadata{
				Annotations: map[string]string{"fizz": "buzz"}},
		}
		// Correct inbound rule
		rulev1 := updateprocessors.RuleAPIV2ToBackend(irule, "namespace2")

		// Assert we don't change the original protocol.
		Expect(irule.Protocol.String()).To(Equal("TCP"))
		Expect(irule.NotProtocol.String()).To(Equal("UDP"))

		// Assert rule converted to v1 is correct
		Expect(rulev1.Action).To(Equal("allow"))
		Expect(rulev1.IPVersion).To(Equal(&v4))
		Expect(rulev1.Protocol.StrVal).To(Equal("tcp"))
		Expect(rulev1.ICMPCode).To(Equal(&icode))
		Expect(rulev1.ICMPType).To(Equal(&itype))
		Expect(rulev1.NotProtocol.StrVal).To(Equal("udp"))
		Expect(rulev1.NotICMPCode).To(Equal(&incode))
		Expect(rulev1.NotICMPType).To(Equal(&intype))

		Expect(rulev1.SrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.10.1/32")}))
		Expect(rulev1.SrcSelector).To(Equal("(projectcalico.org/namespace == 'namespace2') && (mylabel = value1)"))
		Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port80}))
		Expect(rulev1.DstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.1.1/32")}))
		Expect(rulev1.DstSelector).To(Equal("projectcalico.org/namespace == 'namespace2'"))
		Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port443}))

		Expect(rulev1.NotSrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.40.1/32")}))
		Expect(rulev1.NotSrcSelector).To(Equal("has(label1)"))
		Expect(rulev1.NotSrcPorts).To(Equal([]numorstring.Port{port443}))
		Expect(rulev1.NotDstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.80.1/32")}))
		Expect(rulev1.NotDstSelector).To(Equal("has(label2)"))
		Expect(rulev1.NotDstPorts).To(Equal([]numorstring.Port{port80}))

		Expect(rulev1.OriginalSrcSelector).To(Equal("mylabel = value1"))
		Expect(rulev1.OriginalDstSelector).To(Equal(""))
		Expect(rulev1.OriginalSrcNamespaceSelector).To(Equal(""))
		Expect(rulev1.OriginalDstNamespaceSelector).To(Equal(""))
		Expect(rulev1.OriginalNotSrcSelector).To(Equal("has(label1)"))
		Expect(rulev1.OriginalNotDstSelector).To(Equal("has(label2)"))

		Expect(rulev1.OriginalSrcServiceAccountSelector).To(Equal(""))
		Expect(rulev1.OriginalDstServiceAccountSelector).To(Equal(""))
		Expect(rulev1.OriginalSrcServiceAccountNames).To(BeNil())
		Expect(rulev1.OriginalDstServiceAccountNames).To(BeNil())

		Expect(rulev1.HTTPMatch.Methods).To(Equal([]string{"GET", "PUT"}))
		Expect(rulev1.HTTPMatch.Paths).To(Equal([]apiv3.HTTPPath{{Exact: "/bar"}, {Prefix: "/foo1"}}))

		Expect(rulev1.Metadata.Annotations).To(Equal(map[string]string{"fizz": "buzz"}))

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
				Nets:              []string{"10.100.1.1"},
				NamespaceSelector: "namespacelabel1 == 'value1'",
				Ports:             []numorstring.Port{port443},
				NotNets:           []string{"192.168.80.1"},
				NotSelector:       "has(label2)",
				NotPorts:          []numorstring.Port{port80},
			},
			Destination: apiv3.EntityRule{
				Nets:              []string{"10.100.10.1"},
				NamespaceSelector: "namespacelabel2 == 'value2'",
				Ports:             []numorstring.Port{port80},
				NotNets:           []string{"192.168.40.1"},
				NotSelector:       "has(label1)",
				NotPorts:          []numorstring.Port{port443},
			},
		}
		// Correct outbound rule
		rulev1 = updateprocessors.RuleAPIV2ToBackend(erule, "")
		Expect(rulev1.IPVersion).To(Equal(&v4))
		Expect(rulev1.Protocol).To(Equal(&eproto))
		Expect(rulev1.ICMPCode).To(Equal(&ecode))
		Expect(rulev1.ICMPType).To(Equal(&etype))
		Expect(rulev1.NotProtocol).To(Equal(&enproto))
		Expect(rulev1.NotICMPCode).To(Equal(&encode))
		Expect(rulev1.NotICMPType).To(Equal(&entype))

		Expect(rulev1.SrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.1.1/32")}))
		Expect(rulev1.SrcSelector).To(Equal("pcns.namespacelabel1 == \"value1\""))
		Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port443}))
		Expect(rulev1.DstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.10.1/32")}))
		Expect(rulev1.DstSelector).To(Equal("pcns.namespacelabel2 == \"value2\""))
		Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port80}))

		Expect(rulev1.NotSrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.80.1/32")}))
		Expect(rulev1.NotSrcSelector).To(Equal("has(label2)"))
		Expect(rulev1.NotSrcPorts).To(Equal([]numorstring.Port{port80}))
		Expect(rulev1.NotDstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.40.1/32")}))
		Expect(rulev1.NotDstSelector).To(Equal("has(label1)"))
		Expect(rulev1.NotDstPorts).To(Equal([]numorstring.Port{port443}))

		Expect(rulev1.OriginalSrcSelector).To(Equal(""))
		Expect(rulev1.OriginalDstSelector).To(Equal(""))
		Expect(rulev1.OriginalSrcNamespaceSelector).To(Equal("namespacelabel1 == 'value1'"))
		Expect(rulev1.OriginalDstNamespaceSelector).To(Equal("namespacelabel2 == 'value2'"))
		Expect(rulev1.OriginalNotSrcSelector).To(Equal("has(label2)"))
		Expect(rulev1.OriginalNotDstSelector).To(Equal("has(label1)"))

		Expect(rulev1.OriginalSrcServiceAccountSelector).To(Equal(""))
		Expect(rulev1.OriginalDstServiceAccountSelector).To(Equal(""))
		Expect(rulev1.OriginalSrcServiceAccountNames).To(BeNil())
		Expect(rulev1.OriginalDstServiceAccountNames).To(BeNil())

		By("Converting multiple rules")
		rulesv1 := updateprocessors.RulesAPIV2ToBackend([]apiv3.Rule{irule, erule}, "namespace1")
		rulev1 = rulesv1[0]
		Expect(rulev1.Action).To(Equal("allow"))
		Expect(rulev1.IPVersion).To(Equal(&v4))
		Expect(rulev1.Protocol.StrVal).To(Equal("tcp"))
		Expect(rulev1.ICMPCode).To(Equal(&icode))
		Expect(rulev1.ICMPType).To(Equal(&itype))
		Expect(rulev1.NotProtocol.StrVal).To(Equal("udp"))
		Expect(rulev1.NotICMPCode).To(Equal(&incode))
		Expect(rulev1.NotICMPType).To(Equal(&intype))

		Expect(rulev1.SrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.10.1/32")}))
		Expect(rulev1.SrcSelector).To(Equal("(projectcalico.org/namespace == 'namespace1') && (mylabel = value1)"))
		Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port80}))
		Expect(rulev1.DstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.1.1/32")}))
		Expect(rulev1.DstSelector).To(Equal("projectcalico.org/namespace == 'namespace1'"))
		Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port443}))

		Expect(rulev1.NotSrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.40.1/32")}))
		Expect(rulev1.NotSrcSelector).To(Equal("has(label1)"))
		Expect(rulev1.NotSrcPorts).To(Equal([]numorstring.Port{port443}))
		Expect(rulev1.NotDstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.80.1/32")}))
		Expect(rulev1.NotDstSelector).To(Equal("has(label2)"))
		Expect(rulev1.NotDstPorts).To(Equal([]numorstring.Port{port80}))

		Expect(rulev1.OriginalSrcSelector).To(Equal("mylabel = value1"))
		Expect(rulev1.OriginalDstSelector).To(Equal(""))
		Expect(rulev1.OriginalSrcNamespaceSelector).To(Equal(""))
		Expect(rulev1.OriginalDstNamespaceSelector).To(Equal(""))
		Expect(rulev1.OriginalNotSrcSelector).To(Equal("has(label1)"))
		Expect(rulev1.OriginalNotDstSelector).To(Equal("has(label2)"))

		Expect(rulev1.HTTPMatch.Methods).To(Equal([]string{"GET", "PUT"}))
		Expect(rulev1.HTTPMatch.Paths).To(Equal([]apiv3.HTTPPath{{Exact: "/bar"}, {Prefix: "/foo1"}}))

		Expect(rulev1.Metadata.Annotations).To(Equal(map[string]string{"fizz": "buzz"}))

		rulev1 = rulesv1[1]
		Expect(rulev1.IPVersion).To(Equal(&v4))
		Expect(rulev1.Protocol).To(Equal(&eproto))
		Expect(rulev1.ICMPCode).To(Equal(&ecode))
		Expect(rulev1.ICMPType).To(Equal(&etype))
		Expect(rulev1.NotProtocol).To(Equal(&enproto))
		Expect(rulev1.NotICMPCode).To(Equal(&encode))
		Expect(rulev1.NotICMPType).To(Equal(&entype))

		Expect(rulev1.SrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.1.1/32")}))
		// Make sure that the pcns prefix prevented the namespace from making it into the selector.
		Expect(rulev1.SrcSelector).To(Equal("pcns.namespacelabel1 == \"value1\""))
		Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port443}))
		Expect(rulev1.DstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.10.1/32")}))
		Expect(rulev1.DstSelector).To(Equal("pcns.namespacelabel2 == \"value2\""))
		Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port80}))

		Expect(rulev1.NotSrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.80.1/32")}))
		Expect(rulev1.NotSrcSelector).To(Equal("has(label2)"))
		Expect(rulev1.NotSrcPorts).To(Equal([]numorstring.Port{port80}))
		Expect(rulev1.NotDstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.40.1/32")}))
		Expect(rulev1.NotDstSelector).To(Equal("has(label1)"))
		Expect(rulev1.NotDstPorts).To(Equal([]numorstring.Port{port443}))

		Expect(rulev1.OriginalSrcSelector).To(Equal(""))
		Expect(rulev1.OriginalDstSelector).To(Equal(""))
		Expect(rulev1.OriginalSrcNamespaceSelector).To(Equal("namespacelabel1 == 'value1'"))
		Expect(rulev1.OriginalDstNamespaceSelector).To(Equal("namespacelabel2 == 'value2'"))
		Expect(rulev1.OriginalNotSrcSelector).To(Equal("has(label2)"))
		Expect(rulev1.OriginalNotDstSelector).To(Equal("has(label1)"))
	})

	It("should parse a profile rule with no namespace", func() {
		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				Selector: "has(foo)",
			},
			Destination: apiv3.EntityRule{
				Selector: "has(foo)",
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "")

		expected := "has(foo)"
		By("generating the correct source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(expected))
		})

		By("generating the correct destination selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(expected))
		})
	})

	It("should parse a rule with ports but no selectors", func() {
		tcp := numorstring.ProtocolFromString("TCP")
		port80 := numorstring.SinglePort(uint16(80))

		r := apiv3.Rule{
			Action:   apiv3.Allow,
			Protocol: &tcp,
			Source: apiv3.EntityRule{
				Ports: []numorstring.Port{port80},
			},
			Destination: apiv3.EntityRule{
				Ports: []numorstring.Port{port80},
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "")

		By("generating an empty source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(""))
		})

		By("generating the correct ingress ports", func() {
			Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port80}))
		})

		By("generating an empty destination selector", func() {
			Expect(rulev1.DstSelector).To(Equal(""))
		})

		By("generating the correct egress ports", func() {
			Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port80}))
		})

	})

	It("should parse a rule with both a selector and namespace selector", func() {
		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				Selector:          "projectcalico.org/orchestrator == 'k8s'",
				NamespaceSelector: "key == 'value'",
			},
			Destination: apiv3.EntityRule{
				Selector:          "projectcalico.org/orchestrator == 'k8s'",
				NamespaceSelector: "key == 'value'",
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "namespace")

		expected := "(pcns.key == \"value\") && (projectcalico.org/orchestrator == 'k8s')"
		By("generating the correct source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(expected))
		})

		By("generating the correct destination selector", func() {
			Expect(rulev1.DstSelector).To(Equal(expected))
		})
	})

	It("should parse a complex namespace selector", func() {
		s := "!has(key) || (has(key) && !key in {'value'})"
		e := "(!has(pcns.key) || (has(pcns.key) && !pcns.key in {\"value\"}))"

		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				NamespaceSelector: s,
			},
			Destination: apiv3.EntityRule{
				NamespaceSelector: s,
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "namespace")

		By("generating the correct source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(e))
		})

		By("generating the correct destination selector", func() {
			Expect(rulev1.DstSelector).To(Equal(e))
		})
	})

	It("should parse a serviceaccount match", func() {
		srce := fmt.Sprintf("(%s == 'namespace') && ((%skey == \"value1\") && (%s in {\"%s\", \"%s\"}))", apiv3.LabelNamespace, conversion.ServiceAccountLabelPrefix, apiv3.LabelServiceAccount, "sa1", "sa2")
		dste := fmt.Sprintf("(pcns.nskey == \"nsvalue\") && ((%skey == \"value2\") && (%s in {\"%s\"}))", conversion.ServiceAccountLabelPrefix, apiv3.LabelServiceAccount, "sa3")

		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				ServiceAccounts: &apiv3.ServiceAccountMatch{
					Names:    []string{"sa1", "sa2"},
					Selector: "key == 'value1'",
				},
			},
			Destination: apiv3.EntityRule{
				NamespaceSelector: "nskey == 'nsvalue'",
				ServiceAccounts: &apiv3.ServiceAccountMatch{
					Names:    []string{"sa3"},
					Selector: "key == 'value2'",
				},
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "namespace")

		By("generating the correct source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(srce))
			Expect(rulev1.OriginalSrcServiceAccountSelector).To(Equal("key == 'value1'"))
		})

		By("generating the correct destination selector", func() {
			Expect(rulev1.DstSelector).To(Equal(dste))
			Expect(rulev1.OriginalDstServiceAccountSelector).To(Equal("key == 'value2'"))
		})
	})

	It("should parse a serviceaccount match with global namespace and no namespace selector", func() {
		srce := fmt.Sprintf("(%skey == \"value1\") && (%s in {\"%s\", \"%s\"})", conversion.ServiceAccountLabelPrefix, apiv3.LabelServiceAccount, "sa1", "sa2")

		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				ServiceAccounts: &apiv3.ServiceAccountMatch{
					Names:    []string{"sa1", "sa2"},
					Selector: "key == 'value1'",
				},
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "")

		By("generating the correct source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(srce))
		})
	})

	It("should parse an empty serviceaccount match", func() {

		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				ServiceAccounts: &apiv3.ServiceAccountMatch{},
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "")

		By("generating an empty source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(""))
		})
	})

	It("should parse a destination rule services match", func() {
		r := apiv3.Rule{
			Action: apiv3.Allow,
			Destination: apiv3.EntityRule{
				Services: &apiv3.ServiceMatch{
					Name:      "kube-dns",
					Namespace: "kube-system",
				},
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "")

		By("generating an empty source selector", func() {
			Expect(rulev1.SrcSelector).To(Equal(""))
		})

		By("copying the service names", func() {
			Expect(rulev1.DstService).To(Equal("kube-dns"))
			Expect(rulev1.DstServiceNamespace).To(Equal("kube-system"))
		})
	})

	It("should parse a source rule services match", func() {
		r := apiv3.Rule{
			Action: apiv3.Allow,
			Source: apiv3.EntityRule{
				Services: &apiv3.ServiceMatch{
					Name:      "kube-dns",
					Namespace: "kube-system",
				},
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "")

		By("generating an empty destination selector", func() {
			Expect(rulev1.DstSelector).To(Equal(""))
		})

		By("copying the service names", func() {
			Expect(rulev1.SrcService).To(Equal("kube-dns"))
			Expect(rulev1.SrcServiceNamespace).To(Equal("kube-system"))
		})
	})

	It("should parse a serviceaccount match with selector and namespace", func() {
		dste := fmt.Sprintf("(pcns.nskey == \"nsvalue\") && (((%skey == \"value2\") && (%s in {\"%s\"})) && (has(label1)))", conversion.ServiceAccountLabelPrefix, apiv3.LabelServiceAccount, "sa3")

		r := apiv3.Rule{
			Action: apiv3.Allow,
			Destination: apiv3.EntityRule{
				NamespaceSelector: "nskey == 'nsvalue'",
				ServiceAccounts: &apiv3.ServiceAccountMatch{
					Names:    []string{"sa3"},
					Selector: "key == 'value2'",
				},
				Selector: "has(label1)",
			},
		}

		// Process the rule and get the corresponding v1 representation.
		rulev1 := updateprocessors.RuleAPIV2ToBackend(r, "namespace")

		By("generating the correct destination selector", func() {
			Expect(rulev1.DstSelector).To(Equal(dste))
		})
	})

	It("should parse a set of rules and validates the namespaceselector with label and all()", func() {
		rules := []apiv3.Rule{
			{
				Action: apiv3.Allow,
				Destination: apiv3.EntityRule{
					NamespaceSelector: "namespace == 'red'",
					Selector:          "has(label1)",
				},
			},
			{
				Action: apiv3.Allow,
				Destination: apiv3.EntityRule{
					NamespaceSelector: "all()",
					Selector:          "has(label2)",
				},
			},
			{
				Action: apiv3.Allow,
				Destination: apiv3.EntityRule{
					NamespaceSelector: "global()",
					Selector:          "has(label3)",
				},
			},
		}

		outRules := updateprocessors.RulesAPIV2ToBackend(rules, "namespace")
		// The first rule should select "namespace `red`, the second rule should have 'has(projectcalico.org/namespace)'
		// and third rule should select '!has(projectcalico.org/namespace)'
		Expect(outRules[0].DstSelector).To(Equal("(pcns.namespace == \"red\") && (has(label1))"))
		Expect(outRules[1].DstSelector).To(Equal("(has(projectcalico.org/namespace)) && (has(label2))"))
		Expect(outRules[2].DstSelector).To(Equal("(!has(projectcalico.org/namespace)) && (has(label3))"))
	})
})
