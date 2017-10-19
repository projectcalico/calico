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

package resources

import (
	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BGP Peer conversion methods", func() {
	// Create an empty client since we are only testing conversion functions.
	client := NewBGPPeerClient(nil, nil).(*customK8sResourceClient)

	// Define some useful test data.
	listIncomplete := model.ResourceListOptions{}

	// Compatible set of list, key and name
	list1 := model.ResourceListOptions{
		Name: "1-2-3-4",
		Kind: apiv2.KindBGPPeer,
	}

	name1 := "1-2-3-4"
	peerIP1 := net.MustParseIP("1.2.3.4")

	key1 := model.ResourceKey{
		Name: name1,
		Kind: apiv2.KindBGPPeer,
	}

	name2 := "11-22"
	key2 := model.ResourceKey{
		Name: name2,
		Kind: apiv2.KindBGPPeer,
	}

	// Compatible set of KVPair and Kubernetes Resource.
	value1 := apiv2.NewBGPPeer()
	value1.ObjectMeta.Name = name1
	value1.Spec = apiv2.BGPPeerSpec{
		PeerIP:   peerIP1.String(),
		ASNumber: 1212,
	}
	kvp1 := &model.KVPair{
		Key:      key1,
		Value:    value1,
		Revision: "rv",
	}
	res1 := &apiv2.BGPPeer{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv2.KindBGPPeer,
			APIVersion: apiv2.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name1,
			ResourceVersion: "rv",
		},
		Spec: apiv2.BGPPeerSpec{
			ASNumber: 1212,
			PeerIP:   peerIP1.String(),
			Node:     "",
		},
	}

	It("should convert an incomplete ListInterface to no Key", func() {
		Expect(client.listInterfaceToKey(listIncomplete)).To(BeNil())
	})

	It("should convert a qualified ListInterface to the equivalent Key", func() {
		Expect(client.listInterfaceToKey(list1)).To(Equal(key1))
	})

	It("should convert a Key to the equivalent resource name", func() {
		n, err := client.keyToName(key1)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(name1))
	})

	It("should convert a resource name to the equivalent Key", func() {
		k, err := client.nameToKey(name2)
		Expect(err).NotTo(HaveOccurred())
		Expect(k).To(Equal(key2))
	})

	It("should convert between a KVPair and the equivalent Kubernetes resource", func() {
		r, err := client.convertKVPairToResource(kvp1)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.GetObjectMeta().GetName()).To(Equal(res1.ObjectMeta.Name))
		Expect(r.GetObjectMeta().GetResourceVersion()).To(Equal(res1.ObjectMeta.ResourceVersion))
		Expect(r).To(BeAssignableToTypeOf(&apiv2.BGPPeer{}))
		Expect(r.(*apiv2.BGPPeer).Spec).To(Equal(res1.Spec))
	})

	It("should convert between a Kuberenetes resource and the equivalent KVPair", func() {
		kvp, err := client.convertResourceToKVPair(res1)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Key).To(Equal(kvp1.Key))
		Expect(kvp.Revision).To(Equal(kvp1.Revision))
		Expect(kvp.Value.(*apiv2.BGPPeer)).To(BeAssignableToTypeOf(&apiv2.BGPPeer{}))
		Expect(kvp.Value).To(Equal(kvp1.Value))
	})
})
