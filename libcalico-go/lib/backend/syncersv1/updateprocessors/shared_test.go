package updateprocessors_test

import (
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	up "github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var srcSelector string = "mylabel == selector1"
var dstSelector string = "mylabel == selector2"
var notSrcSelector string = "has(label1)"
var notDstSelector string = "has(label2)"

// v1 and v3 ingress rule.
var v4 = 4
var itype = 1
var intype = 3
var icode = 4
var incode = 6
var ProtocolTCPV1 = numorstring.ProtocolFromStringV1("tcp")
var ProtocolUDPV1 = numorstring.ProtocolFromStringV1("udp")
var port80 = numorstring.SinglePort(uint16(80))
var Port443 = numorstring.SinglePort(uint16(443))
var ProtocolTCPv3 = numorstring.ProtocolFromString("TCP")
var ProtocolUDPv3 = numorstring.ProtocolFromString("UDP")

var v1TestIngressRule = model.Rule{
	Action:      "allow",
	IPVersion:   &v4,
	Protocol:    &ProtocolTCPV1,
	NotProtocol: &ProtocolUDPV1,
	ICMPType:    &itype,
	ICMPCode:    &icode,
	NotICMPType: &intype,
	NotICMPCode: &incode,

	SrcNets:     up.ConvertStringsToNets([]string{"10.100.10.1"}),
	SrcSelector: "mylabel == selector1",
	SrcPorts:    []numorstring.Port{port80},
	DstNets:     up.NormalizeIPNets([]string{"10.100.1.1"}),
	DstSelector: "mylabel == selector2",
	DstPorts:    []numorstring.Port{Port443},

	NotSrcNets:     up.ConvertStringsToNets([]string{"192.168.40.1"}),
	NotSrcSelector: "has(label1)",
	NotSrcPorts:    []numorstring.Port{Port443},
	NotDstNets:     up.NormalizeIPNets([]string{"192.168.80.1"}),
	NotDstSelector: "has(label2)",
	NotDstPorts:    []numorstring.Port{port80},

	OriginalSrcSelector:    "mylabel == selector1",
	OriginalDstSelector:    "mylabel == selector2",
	OriginalNotSrcSelector: "has(label1)",
	OriginalNotDstSelector: "has(label2)",
}

var v3TestIngressRule = apiv3.Rule{
	Action:      apiv3.Allow,
	IPVersion:   &v4,
	Protocol:    &ProtocolTCPv3,
	ICMP:        &apiv3.ICMPFields{Type: &itype, Code: &icode},
	NotProtocol: &ProtocolUDPv3,
	NotICMP:     &apiv3.ICMPFields{Type: &intype, Code: &incode},
	Source: apiv3.EntityRule{
		Nets:        []string{"10.100.10.1"},
		Selector:    "mylabel == selector1",
		Ports:       []numorstring.Port{port80},
		NotNets:     []string{"192.168.40.1"},
		NotSelector: "has(label1)",
		NotPorts:    []numorstring.Port{Port443},
	},
	Destination: apiv3.EntityRule{
		Nets:        []string{"10.100.1.1"},
		Selector:    "mylabel == selector2",
		Ports:       []numorstring.Port{Port443},
		NotNets:     []string{"192.168.80.1"},
		NotSelector: "has(label2)",
		NotPorts:    []numorstring.Port{port80},
	},
}

// v1 and v3 egress rule.
var etype = 2
var entype = 7
var ecode = 5
var encode = 8
var eproto = numorstring.ProtocolFromInt(uint8(30))
var enproto = numorstring.ProtocolFromInt(uint8(62))

var v1TestEgressRule = model.Rule{
	Action:      "allow",
	IPVersion:   &v4,
	Protocol:    &eproto,
	ICMPCode:    &ecode,
	ICMPType:    &etype,
	NotProtocol: &enproto,
	NotICMPCode: &encode,
	NotICMPType: &entype,

	SrcNets:     up.ConvertStringsToNets([]string{"10.100.1.1"}),
	SrcSelector: "mylabel == selector2",
	SrcPorts:    []numorstring.Port{Port443},
	DstNets:     up.NormalizeIPNets([]string{"10.100.10.1"}),
	DstSelector: "mylabel == selector1",
	DstPorts:    []numorstring.Port{port80},

	NotSrcNets:     up.ConvertStringsToNets([]string{"192.168.80.1"}),
	NotSrcSelector: "has(label2)",
	NotSrcPorts:    []numorstring.Port{port80},
	NotDstNets:     up.NormalizeIPNets([]string{"192.168.40.1"}),
	NotDstSelector: "has(label1)",
	NotDstPorts:    []numorstring.Port{Port443},

	OriginalSrcSelector:    "mylabel == selector2",
	OriginalDstSelector:    "mylabel == selector1",
	OriginalNotSrcSelector: "has(label2)",
	OriginalNotDstSelector: "has(label1)",
}

var v3TestEgressRule = apiv3.Rule{
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
		Selector:    "mylabel == selector2",
		Ports:       []numorstring.Port{Port443},
		NotNets:     []string{"192.168.80.1"},
		NotSelector: "has(label2)",
		NotPorts:    []numorstring.Port{port80},
	},
	Destination: apiv3.EntityRule{
		Nets:        []string{"10.100.10.1"},
		Selector:    "mylabel == selector1",
		Ports:       []numorstring.Port{port80},
		NotNets:     []string{"192.168.40.1"},
		NotSelector: "has(label1)",
		NotPorts:    []numorstring.Port{Port443},
	},
}

var testPolicyOrder101 = float64(101)
var testDefaultPolicyOrder = float64(1000)

// v3 model.KVPair revision
var testRev string = "1234"

func mustParseCIDR(cidr string) *cnet.IPNet {
	ipn := cnet.MustParseCIDR(cidr)
	return &ipn
}

// fullGNPv1 returns a v1 GNP with all fields filled out.
func fullGNPv1() (p model.Policy) {
	return model.Policy{
		Order:          &testPolicyOrder101,
		DoNotTrack:     true,
		InboundRules:   []model.Rule{v1TestIngressRule},
		OutboundRules:  []model.Rule{v1TestEgressRule},
		PreDNAT:        false,
		ApplyOnForward: true,
		Types:          []string{"ingress", "egress"},
	}
}

// fullGNPv3 returns a v3 GNP with all fields filled out.
func fullGNPv3(namespace, selector string) *apiv3.GlobalNetworkPolicy {
	fullGNP := apiv3.NewGlobalNetworkPolicy()
	fullGNP.Namespace = namespace
	fullGNP.Spec.Order = &testPolicyOrder101
	fullGNP.Spec.Ingress = []apiv3.Rule{v3TestIngressRule}
	fullGNP.Spec.Egress = []apiv3.Rule{v3TestEgressRule}
	fullGNP.Spec.Selector = selector
	fullGNP.Spec.DoNotTrack = true
	fullGNP.Spec.PreDNAT = false
	fullGNP.Spec.ApplyOnForward = true
	fullGNP.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress}
	return fullGNP
}

// fullNPv1 returns a v1 NP with all fields filled out.
func fullNPv1(namespace string) (p model.Policy) {
	ir := v1TestIngressRule
	or := v1TestEgressRule
	if namespace != "" {
		ir.SrcSelector = fmt.Sprintf("(projectcalico.org/namespace == '%s') && (%s)", namespace, ir.SrcSelector)
		ir.DstSelector = fmt.Sprintf("(projectcalico.org/namespace == '%s') && (%s)", namespace, ir.DstSelector)
		or.SrcSelector = fmt.Sprintf("(projectcalico.org/namespace == '%s') && (%s)", namespace, or.SrcSelector)
		or.DstSelector = fmt.Sprintf("(projectcalico.org/namespace == '%s') && (%s)", namespace, or.DstSelector)
	}

	return model.Policy{
		Namespace:      namespace,
		Order:          &testPolicyOrder101,
		InboundRules:   []model.Rule{ir},
		OutboundRules:  []model.Rule{or},
		ApplyOnForward: true,
		Types:          []string{"ingress", "egress"},
	}
}

// fullNPv3 returns a v3 NP with all fields filled out.
func fullNPv3(name, namespace, selector string) *apiv3.NetworkPolicy {
	fullNP := apiv3.NewNetworkPolicy()
	fullNP.Name = name
	fullNP.Namespace = namespace
	fullNP.Spec.Order = &testPolicyOrder101
	fullNP.Spec.Ingress = []apiv3.Rule{v3TestIngressRule}
	fullNP.Spec.Egress = []apiv3.Rule{v3TestEgressRule}
	fullNP.Spec.Selector = selector
	fullNP.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress}

	return fullNP
}
