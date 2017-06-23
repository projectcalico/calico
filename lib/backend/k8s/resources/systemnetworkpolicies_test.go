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
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("System Network Policies conversion methods", func() {

	converter := resources.SystemNetworkPolicyConverter{}

	// Define some useful test data.
	listIncomplete := model.PolicyListOptions{}
	keyInvalid := model.PolicyKey{
		Name: "foo.bar",
	}

	// Compatible set of list, key and name
	list1 := model.PolicyListOptions{
		Name: "snp.projectcalico.org/abcd",
	}
	key1 := model.PolicyKey{
		Name: "snp.projectcalico.org/abcd",
	}
	name1 := "abcd"

	// Compatible set of key and name
	key2 := model.PolicyKey{
		Name: "snp.projectcalico.org/foo.bar",
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
		},
		Revision: "rv",
	}

	res1 := &thirdparty.SystemNetworkPolicy{
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
		},
	}

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

	It("should fail to convert an invalid Key to a resource name", func() {
		_, err := converter.KeyToName(keyInvalid)
		Expect(err).To(HaveOccurred())
	})

	It("should convert between a KVPair and the equivalent Kubernetes resource", func() {
		r, err := converter.FromKVPair(kvp1)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.GetObjectMeta().GetName()).To(Equal(res1.Metadata.Name))
		Expect(r.GetObjectMeta().GetResourceVersion()).To(Equal(res1.Metadata.ResourceVersion))
		Expect(r).To(BeAssignableToTypeOf(&thirdparty.SystemNetworkPolicy{}))
		Expect(r.(*thirdparty.SystemNetworkPolicy).Spec).To(Equal(res1.Spec))
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
