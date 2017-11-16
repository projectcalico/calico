package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
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
		}
		// Correct inbound rule
		rulev1 := updateprocessors.RuleAPIV2ToBackend(irule, "namespace2")
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
			Expect(rulev1.SrcSelector).To(Equal(e))
		})
	})
})
