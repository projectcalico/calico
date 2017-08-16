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
	"github.com/projectcalico/libcalico-go/lib/net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("IP Pool conversion methods", func() {

	converter := resources.IPPoolConverter{}

	// Define some useful test data.
	listIncomplete := model.IPPoolListOptions{}

	// Compatible set of list, key and name
	list1 := model.IPPoolListOptions{
		CIDR: net.MustParseNetwork("1.2.3.0/24"),
	}
	key1 := model.IPPoolKey{
		CIDR: net.MustParseNetwork("1.2.3.0/24"),
	}
	name1 := "1-2-3-0-24"

	// Compatible set of key and name
	key2 := model.IPPoolKey{
		CIDR: net.MustParseNetwork("11:22::/120"),
	}
	name2 := "11-22---120"

	// Compatible set of KVPair and Kubernetes Resource.
	kvp1 := &model.KVPair{
		Key: key2,
		Value: &model.IPPool{
			CIDR:          key2.CIDR,
			Masquerade:    true,
			IPIPMode:      "cross-subnet",
			IPIPInterface: "tunl0",
			Disabled:      false,
			IPAM:          true,
		},
		Revision: "rv",
	}
	res1 := &custom.IPPool{
		Metadata: metav1.ObjectMeta{
			Name:            name2,
			ResourceVersion: "rv",
		},
		Spec: custom.IPPoolSpec{
			IPPoolSpec: api.IPPoolSpec{
				IPIP: &api.IPIPConfiguration{
					Enabled: true,
					Mode:    "cross-subnet",
				},
				NATOutgoing: true,
				Disabled:    false,
			},
			CIDR: key2.CIDR,
		},
	}

	// Invalid Kubernetes resource, invalid name
	nameInvalid := "11-22-fail--23"

	resInvalidName := &custom.IPPool{
		Metadata: metav1.ObjectMeta{
			Name:            nameInvalid,
			ResourceVersion: "test",
		},
		Spec: custom.IPPoolSpec{},
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

	It("should fail to convert an invalid resource name to the equivalent Key", func() {
		k, err := converter.NameToKey(nameInvalid)
		Expect(err).To(HaveOccurred())
		Expect(k).To(BeNil())
	})

	It("should convert between a KVPair and the equivalent Kubernetes resource", func() {
		r, err := converter.FromKVPair(kvp1)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.GetObjectMeta().GetName()).To(Equal(res1.Metadata.Name))
		Expect(r.GetObjectMeta().GetResourceVersion()).To(Equal(res1.Metadata.ResourceVersion))
		Expect(r).To(BeAssignableToTypeOf(&custom.IPPool{}))
	})

	It("should convert between a Kuberenetes resource and the equivalent KVPair", func() {
		kvp, err := converter.ToKVPair(res1)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Key).To(Equal(kvp1.Key))
		Expect(kvp.Revision).To(Equal(kvp1.Revision))
		Expect(kvp.Value).To(BeAssignableToTypeOf(&model.IPPool{}))
		Expect(kvp.Value).To(Equal(kvp1.Value))
	})

	It("should fail to convert an invalid Kuberenetes resource (invalid name)", func() {
		_, err := converter.ToKVPair(resInvalidName)
		Expect(err).To(HaveOccurred())
	})
})
