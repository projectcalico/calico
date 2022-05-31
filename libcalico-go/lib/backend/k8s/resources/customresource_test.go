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
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Custom resource conversion methods (tested using BGPPeer)", func() {
	// Create an empty client since we are only testing conversion functions.
	client := NewBGPPeerClient(nil, nil).(*customK8sResourceClient)

	// Define some useful test data.
	listIncomplete := model.ResourceListOptions{}

	// Compatible set of list, key and name
	list1 := model.ResourceListOptions{
		Name: "1-2-3-4",
		Kind: apiv3.KindBGPPeer,
	}

	name1 := "1-2-3-4"
	peerIP1 := net.MustParseIP("1.2.3.4")

	key1 := model.ResourceKey{
		Name: name1,
		Kind: apiv3.KindBGPPeer,
	}

	name2 := "11-22"
	key2 := model.ResourceKey{
		Name: name2,
		Kind: apiv3.KindBGPPeer,
	}

	// Compatible set of KVPair and Kubernetes Resource.
	value1 := apiv3.NewBGPPeer()
	value1.ObjectMeta.Name = name1
	value1.ObjectMeta.ResourceVersion = "rv"
	value1.Spec = apiv3.BGPPeerSpec{
		PeerIP:   peerIP1.String(),
		ASNumber: 1212,
	}
	kvp1 := &model.KVPair{
		Key:      key1,
		Value:    value1,
		Revision: "rv",
	}
	res1 := &apiv3.BGPPeer{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindBGPPeer,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name1,
			ResourceVersion: "rv",
		},
		Spec: apiv3.BGPPeerSpec{
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
		Expect(r).To(BeAssignableToTypeOf(&apiv3.BGPPeer{}))
		Expect(r.(*apiv3.BGPPeer).Spec).To(Equal(res1.Spec))

		// Make sure to clean up the annotations on the resource
		err = ConvertK8sResourceToCalicoResource(r)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should convert between a Kubernetes resource and the equivalent KVPair", func() {
		// Make sure it returns the same resource if a resource is given without Calico metadata annotations.
		kvp, err := client.convertResourceToKVPair(res1)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Value).To(Equal(res1))

		// Convert the values into the annotations.
		resConverted, err := ConvertCalicoResourceToK8sResource(res1)
		Expect(err).NotTo(HaveOccurred())

		kvp, err = client.convertResourceToKVPair(resConverted)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Key).To(Equal(kvp1.Key))
		Expect(kvp.Revision).To(Equal(kvp1.Revision))
		Expect(kvp.Value).To(BeAssignableToTypeOf(&apiv3.BGPPeer{}))
		Expect(kvp.Value).To(Equal(kvp1.Value))
	})
})
