// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package resources_test

import (
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/custom"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Global Network Policies conversion methods", func() {

	converter := resources.GlobalNetworkPolicyConverter{}

	// Define some useful test data.
	listIncomplete := model.PolicyListOptions{}

	// Compatible set of list, key and name
	list1 := model.PolicyListOptions{
		Name: "abcd",
	}
	key1 := model.PolicyKey{
		Name: "abcd",
	}
	name1 := "abcd"

	// Compatible set of key and name
	key2 := model.PolicyKey{
		Name: "foo.bar",
	}
	name2 := "foo.bar"

	// Compatible set of KVPair and Kubernetes Resource.
	order := float64(2.0)
	prot := numorstring.ProtocolFromString("tcp")
	port, _ := numorstring.PortFromRange(10, 20)
	kvp1 := &model.KVPair{
		Key: key2,
		Value: &model.Policy{
			Order: &order,
			InboundRules: []model.Rule{{
				Action:      "deny",
				Protocol:    &prot,
				SrcSelector: "has(bazfoo)",
			}},
			OutboundRules: []model.Rule{{
				Action:   "allow",
				DstPorts: []numorstring.Port{port},
			}},
			Selector:   "has(foobar)",
			DoNotTrack: true,
			Types:      []string{"ingress", "egress"},
		},
		Revision: "rv",
	}

	res1 := &custom.GlobalNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name:            name2,
			ResourceVersion: "rv",
		},
		Spec: api.PolicySpec{
			Order: &order,
			IngressRules: []api.Rule{{
				Action:   "deny",
				Protocol: &prot,
				Source: api.EntityRule{
					Selector: "has(bazfoo)",
				},
			}},
			EgressRules: []api.Rule{{
				Action: "allow",
				Destination: api.EntityRule{
					Ports: []numorstring.Port{port},
				},
			}},
			Selector:   "has(foobar)",
			DoNotTrack: true,
			Types:      []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress},
		},
	}

	Context("with pre-DNAT flag", func() {

		BeforeEach(func() {
			kvp1.Value.(*model.Policy).DoNotTrack = false
			kvp1.Value.(*model.Policy).PreDNAT = true
			kvp1.Value.(*model.Policy).ApplyOnForward = true
			res1.Spec.DoNotTrack = false
			res1.Spec.PreDNAT = true
			res1.Spec.ApplyOnForward = true
		})

		AfterEach(func() {
			kvp1.Value.(*model.Policy).DoNotTrack = true
			kvp1.Value.(*model.Policy).PreDNAT = false
			kvp1.Value.(*model.Policy).ApplyOnForward = true
			res1.Spec.DoNotTrack = true
			res1.Spec.PreDNAT = false
			res1.Spec.ApplyOnForward = true
		})

		It("should convert between a KVPair and the equivalent Kubernetes resource", func() {
			r, err := converter.FromKVPair(kvp1)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.GetObjectMeta().GetName()).To(Equal(res1.Metadata.Name))
			Expect(r.GetObjectMeta().GetResourceVersion()).To(Equal(res1.Metadata.ResourceVersion))
			Expect(r).To(BeAssignableToTypeOf(&custom.GlobalNetworkPolicy{}))
			Expect(r.(*custom.GlobalNetworkPolicy).Spec).To(Equal(res1.Spec))
		})

		It("should convert between a Kuberenetes resource and the equivalent KVPair", func() {
			kvp, err := converter.ToKVPair(res1)
			Expect(err).NotTo(HaveOccurred())
			Expect(kvp.Key).To(Equal(kvp1.Key))
			Expect(kvp.Revision).To(Equal(kvp1.Revision))
			Expect(kvp.Value).To(BeAssignableToTypeOf(&model.Policy{}))
			Expect(kvp.Value).To(Equal(kvp1.Value))
		})
	})

	It("should convert an incomplete ListInterface to no Key", func() {
		Expect(converter.ListInterfaceToKey(listIncomplete)).To(BeNil())
	})

	It("should convert a qualified ListInterface to the equivalent Key", func() {
		Expect(converter.ListInterfaceToKey(list1)).To(Equal(key1))
	})

	It("should convert a Key to the equivalent resource name", func() {
		n, err := converter.KeyToName(key1)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(name1))
	})

	It("should convert a resource name to the equivalent Key", func() {
		k, err := converter.NameToKey(name2)
		Expect(err).NotTo(HaveOccurred())
		Expect(k).To(Equal(key2))
	})

	It("should convert between a KVPair and the equivalent Kubernetes resource", func() {
		r, err := converter.FromKVPair(kvp1)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.GetObjectMeta().GetName()).To(Equal(res1.Metadata.Name))
		Expect(r.GetObjectMeta().GetResourceVersion()).To(Equal(res1.Metadata.ResourceVersion))
		Expect(r).To(BeAssignableToTypeOf(&custom.GlobalNetworkPolicy{}))
		Expect(r.(*custom.GlobalNetworkPolicy).Spec).To(Equal(res1.Spec))
	})

	It("should convert between a Kuberenetes resource and the equivalent KVPair", func() {
		kvp, err := converter.ToKVPair(res1)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Key).To(Equal(kvp1.Key))
		Expect(kvp.Revision).To(Equal(kvp1.Revision))
		Expect(kvp.Value).To(BeAssignableToTypeOf(&model.Policy{}))
		Expect(kvp.Value).To(Equal(kvp1.Value))
	})
})
