// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
)

var (
	// stagednpExtraFields is the set of fields that should be in StagedNetworkPolicy but not
	// NetworkPolicy.
	stagednpExtraFields = From("StagedAction")

	// networkPolicyExtraFields is the set of fields that should be in NetworkPolicy but not
	// StagedNetworkPolicy.
	networkPolicyExtraFields = From()
)

// These tests verify that the StagedNetworkPolicySpec struct and the NetworkPolicySpec struct
// are kept in sync.
var _ = Describe("StagedNetworkPolicySpec", func() {
	var snpFieldsByName map[string]reflect.StructField
	var npFieldsByName map[string]reflect.StructField

	BeforeEach(func() {
		snpFieldsByName = fieldsByName(apiv3.StagedNetworkPolicySpec{})
		npFieldsByName = fieldsByName(apiv3.NetworkPolicySpec{})
	})

	It("and NetworkPolicySpec shared fields should have the same tags", func() {
		for n, f := range snpFieldsByName {
			if gf, ok := npFieldsByName[n]; ok {
				if f.Name != "Selector" { //selector tags are not same. selector is not required for staged policy
					Expect(f.Tag).To(Equal(gf.Tag), "Field "+n+" had different tag")
				}
			}
		}
	})

	It("and NetworkPolicySpec shared fields should have the same types", func() {
		for n, f := range snpFieldsByName {
			if gf, ok := npFieldsByName[n]; ok {
				Expect(f.Type).To(Equal(gf.Type), "Field "+n+" had different type")
			}
		}
	})

	It("should not have any unexpected fields that NetworkPolicySpec doesn't have", func() {
		for n := range snpFieldsByName {
			if stagednpExtraFields.Contains(n) {
				continue
			}
			Expect(npFieldsByName).To(HaveKey(n))
		}
	})

	It("should contain all expected fields of NetworkPolicySpec", func() {
		for n := range npFieldsByName {
			if networkPolicyExtraFields.Contains(n) {
				continue
			}
			Expect(snpFieldsByName).To(HaveKey(n))
		}
	})

	It("should be able to properly convert from staged to enforced", func() {
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
				Selector:    "mylabel = value1",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.1.1"},
				Selector:    "",
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
				Selector:    "pcns.namespacelabel1 == 'value1'",
				Ports:       []numorstring.Port{port443},
				NotNets:     []string{"192.168.80.1"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.10.1"},
				Selector:    "pcns.namespacelabel2 == 'value2'",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
		}
		order := float64(101)
		selector := "mylabel == selectme"

		staged := apiv3.NewStagedNetworkPolicy()
		staged.Name = "juventus"
		staged.Namespace = "champion"
		staged.Spec.Order = &order
		staged.Spec.Ingress = []apiv3.Rule{irule}
		staged.Spec.Egress = []apiv3.Rule{erule}
		staged.Spec.Selector = selector
		staged.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress}
		staged.Spec.StagedAction = apiv3.StagedActionSet

		stagedAction, enforced := apiv3.ConvertStagedPolicyToEnforced(staged)

		//TODO: mgianluc all common fields should be checked, though following is good enough coverage
		Expect(stagedAction).To(Equal(staged.Spec.StagedAction))
		Expect(enforced.Spec.Ingress).To(Equal(staged.Spec.Ingress))
		Expect(enforced.Spec.Egress).To(Equal(staged.Spec.Egress))
		Expect(enforced.Spec.Selector).To(Equal(staged.Spec.Selector))
		Expect(enforced.Spec.Order).To(Equal(staged.Spec.Order))
		Expect(enforced.Namespace).To(Equal(staged.Namespace))
		Expect(enforced.Name).To(Equal(staged.Name))
	})
})
