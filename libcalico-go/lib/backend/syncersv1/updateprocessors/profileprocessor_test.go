// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the Profile update processor", func() {
	name1 := "name1"
	name2 := "name2"
	nilRules := &model.ProfileRules{}

	v3ProfileKey1 := model.ResourceKey{
		Kind: apiv3.KindProfile,
		Name: name1,
	}
	v3ProfileKey2 := model.ResourceKey{
		Kind: apiv3.KindProfile,
		Name: name2,
	}
	v1ProfileKey1 := model.ProfileKey{
		Name: name1,
	}
	v1ProfileKey2 := model.ProfileKey{
		Name: name2,
	}

	It("should handle conversion of valid Profiles", func() {
		up := updateprocessors.NewProfileUpdateProcessor()

		By("converting a Profile with minimum configuration")
		res := apiv3.NewProfile()
		res.Spec.LabelsToApply = map[string]string{"testLabel": "label"}

		kvps, err := up.Process(&model.KVPair{
			Key:      v3ProfileKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(3))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key:      model.ProfileLabelsKey{v1ProfileKey1},
			Value:    map[string]string{"testLabel": "label"},
			Revision: "abcde",
		}))
		Expect(kvps[1]).To(Equal(&model.KVPair{
			Key:      model.ProfileRulesKey{v1ProfileKey1},
			Value:    nilRules,
			Revision: "abcde",
		}))

		By("adding another Profile with a full configuration")
		res = apiv3.NewProfile()
		res.Spec.LabelsToApply = map[string]string{"testLabel": "label2"}

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

		res.Spec.Ingress = []apiv3.Rule{irule}
		res.Spec.Egress = []apiv3.Rule{erule}
		kvps, err = up.Process(&model.KVPair{
			Key:      v3ProfileKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		v1irule := updateprocessors.RuleAPIV2ToBackend(irule, "")
		v1erule := updateprocessors.RuleAPIV2ToBackend(erule, "")
		Expect(kvps).To(HaveLen(3))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key:      model.ProfileLabelsKey{v1ProfileKey2},
			Value:    map[string]string{"testLabel": "label2"},
			Revision: "1234",
		}))
		Expect(kvps[1]).To(Equal(&model.KVPair{
			Key: model.ProfileRulesKey{v1ProfileKey2},
			Value: &model.ProfileRules{
				InboundRules:  []model.Rule{v1irule},
				OutboundRules: []model.Rule{v1erule},
			},
			Revision: "1234",
		}))

		By("deleting the first profile")
		kvps, err = up.Process(&model.KVPair{
			Key:   v3ProfileKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   model.ProfileLabelsKey{v1ProfileKey1},
				Value: nil,
			},
			{
				Key:   model.ProfileRulesKey{v1ProfileKey1},
				Value: nil,
			},
			{
				Key:   v3ProfileKey1,
				Value: nil,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewProfileUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewProfile()

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv3.NewHostEndpoint()

		kvps, err := up.Process(&model.KVPair{
			Key:      v3ProfileKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   model.ProfileLabelsKey{v1ProfileKey1},
				Value: nil,
			},
			{
				Key:   model.ProfileRulesKey{v1ProfileKey1},
				Value: nil,
			},
			{
				Key:      v3ProfileKey1,
				Value:    nil,
				Revision: "abcde",
			},
		}))

		By("trying to convert without enough information to create a v1 key")
		eres := apiv3.NewProfile()
		v3ProfileKeyEmpty := model.ResourceKey{
			Kind: apiv3.KindProfile,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v3ProfileKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
