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
	"github.com/projectcalico/libcalico-go/lib/net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Global BGP conversion methods", func() {

	converter := resources.GlobalBGPPeerConverter{}

	// Define some useful test data.
	listIncomplete := model.GlobalBGPPeerListOptions{}
	nameInvalid := "11-22-fail--23"

	// Compatible set of list, key and name
	list1 := model.GlobalBGPPeerListOptions{
		PeerIP: net.MustParseIP("1.2.3.4"),
	}
	key1 := model.GlobalBGPPeerKey{
		PeerIP: net.MustParseIP("1.2.3.4"),
	}
	name1 := "1-2-3-4"

	// Compatible set of key and name
	key2 := model.GlobalBGPPeerKey{
		PeerIP: net.MustParseIP("11:22::"),
	}
	name2 := "11-22--"

	// Compatible set of KVPair and Kubernetes Resource.
	kvp1 := &model.KVPair{
		Key: key2,
		Value: &model.BGPPeer{
			PeerIP: key2.PeerIP,
			ASNum:  1212,
		},
		Revision: "rv",
	}
	res1 := &thirdparty.GlobalBgpPeer{
		Metadata: metav1.ObjectMeta{
			Name:            name2,
			ResourceVersion: "rv",
		},
		Spec: api.BGPPeerSpec{
			ASNumber: 1212,
		},
	}

	// Invalid Kubernetes resource, invalid name
	resInvalid := &thirdparty.GlobalBgpPeer{
		Metadata: metav1.ObjectMeta{
			Name:            nameInvalid,
			ResourceVersion: "test",
		},
		Spec: api.BGPPeerSpec{
			ASNumber: 1234,
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
		Expect(r).To(BeAssignableToTypeOf(&thirdparty.GlobalBgpPeer{}))
		Expect(r.(*thirdparty.GlobalBgpPeer).Spec).To(Equal(res1.Spec))
	})

	It("should convert between a Kuberenetes resource and the equivalent KVPair", func() {
		kvp, err := converter.ToKVPair(res1)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Key).To(Equal(kvp1.Key))
		Expect(kvp.Revision).To(Equal(kvp1.Revision))
		Expect(kvp.Value).To(BeAssignableToTypeOf(&model.BGPPeer{}))
		Expect(kvp.Value).To(Equal(kvp1.Value))
	})

	It("should fail to convert an invalid Kuberenetes resource", func() {
		_, err := converter.ToKVPair(resInvalid)
		Expect(err).To(HaveOccurred())
	})
})
