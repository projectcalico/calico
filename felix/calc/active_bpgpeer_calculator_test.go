// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package calc

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	libv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

var _ = Describe("ActiveBGPPeerCalculator", func() {
	var abp *ActiveBGPPeerCalculator

	var result map[string]string

	hostname := "my-host"

	onEndpointBGPPeerDataUpdate := func(id model.WorkloadEndpointKey, peerData *EpPeerData) {
		// Result maps workload name to bgp peer name.
		if peerData != nil {
			result[id.WorkloadID] = peerData.v3PeerName
		} else {
			delete(result, id.WorkloadID)
		}
	}

	BeforeEach(func() {
		abp = NewActiveBGPPeerCalculator(hostname)
		abp.OnEndpointBGPPeerDataUpdate = onEndpointBGPPeerDataUpdate

		// Clean result map.
		result = make(map[string]string)

		// Add two endpoints with color=red, one with color=blue and one with color=yellow.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:   hostname,
					WorkloadID: "w-red",
				},
				Value: &model.WorkloadEndpoint{
					Name:   "w-red",
					Labels: map[string]string{"color": "red"},
				},
			},
		})

		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:   hostname,
					WorkloadID: "w-blue",
				},
				Value: &model.WorkloadEndpoint{
					Name:   "w-blue",
					Labels: map[string]string{"color": "blue"},
				},
			},
		})

		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:   hostname,
					WorkloadID: "w-yellow",
				},
				Value: &model.WorkloadEndpoint{
					Name:   "w-yellow",
					Labels: map[string]string{"color": "yellow"},
				},
			},
		})

		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:   hostname,
					WorkloadID: "w-red-2",
				},
				Value: &model.WorkloadEndpoint{
					Name:   "w-red-2",
					Labels: map[string]string{"color": "red"},
				},
			},
		})

		// Add host update.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: libv3.KindNode, Name: hostname},
				Value: &libv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   hostname,
						Labels: map[string]string{"host": "my-host"},
					},
				},
			},
		})

		// Global peer to select red endpoints.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindBGPPeer, Name: "global-peer-red"},
				Value: &v3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "global-peer-red",
					},
					Spec: v3.BGPPeerSpec{
						LocalWorkloadSelector: "color == 'red'",
					},
				},
			},
		})

		// Node specific peer on my host to select blue endpoints.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindBGPPeer, Name: "node-specific-peer-my-host-blue"},
				Value: &v3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-specific-peer-my-host-blue",
					},
					Spec: v3.BGPPeerSpec{
						NodeSelector:          "host=='my-host'",
						LocalWorkloadSelector: "color == 'blue'",
					},
				},
			},
		})

		// Node specific peer on other host to select yellow endpoints.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindBGPPeer, Name: "node-specific-peer-other-host-yellow"},
				Value: &v3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-specific-peer-other-host-yellow",
					},
					Spec: v3.BGPPeerSpec{
						NodeSelector:          "host=='other-host'",
						LocalWorkloadSelector: "color == 'yellow'",
					},
				},
			},
		})
	})

	It("Should set correct bgp peer data", func() {
		Expect(result["w-red"]).To(Equal("global-peer-red"))
		Expect(result["w-red-2"]).To(Equal("global-peer-red"))
		Expect(result["w-blue"]).To(Equal("node-specific-peer-my-host-blue"))
		Expect(result["w-yellow"]).NotTo(Equal("node-specific-peer-other-host-yellow"))
	})

	It("Should set correct bgp peer data on endpoint labels update", func() {
		// Turn w-red-2 to blue.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{
					Hostname:   hostname,
					WorkloadID: "w-red-2",
				},
				Value: &model.WorkloadEndpoint{
					Name:   "w-red-2",
					Labels: map[string]string{"color": "blue"},
				},
			},
		})

		Expect(result["w-red"]).To(Equal("global-peer-red"))
		Expect(result["w-red-2"]).To(Equal("node-specific-peer-my-host-blue"))
		Expect(result["w-blue"]).To(Equal("node-specific-peer-my-host-blue"))
		Expect(result["w-yellow"]).NotTo(Equal("node-specific-peer-other-host-yellow"))
	})

	It("Should remove correct bgp peer data for endpoints", func() {
		// Global peer red to select blue endpoints.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindBGPPeer, Name: "global-peer-red"},
				Value: &v3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "global-peer-red",
					},
					Spec: v3.BGPPeerSpec{
						LocalWorkloadSelector: "color == 'blue'",
					},
				},
			},
		})

		// Node specific peer blue on my host to select yellow endpoints.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindBGPPeer, Name: "node-specific-peer-my-host-blue"},
				Value: &v3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-specific-peer-my-host-blue",
					},
					Spec: v3.BGPPeerSpec{
						NodeSelector:          "host=='my-host'",
						LocalWorkloadSelector: "color == 'yellow'",
					},
				},
			},
		})

		Expect(result["w-red"]).NotTo(Equal("global-peer-red"))
		Expect(result["w-red-2"]).NotTo(Equal("global-peer-red"))
		Expect(result["w-blue"]).To(Equal("global-peer-red"))
		Expect(result["w-yellow"]).To(Equal("node-specific-peer-my-host-blue"))
	})

	It("Should set correct bgp peer data on node labels update", func() {
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: libv3.KindNode, Name: hostname},
				Value: &libv3.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   hostname,
						Labels: map[string]string{"host": "other-host"},
					},
				},
			},
		})

		Expect(result["w-red"]).To(Equal("global-peer-red"))
		Expect(result["w-red-2"]).To(Equal("global-peer-red"))
		Expect(result["w-blue"]).NotTo(Equal("node-specific-peer-my-host-blue"))
		Expect(result["w-yellow"]).To(Equal("node-specific-peer-other-host-yellow"))
	})

	It("Should set correct bgp peer data on BGP peer update on node", func() {
		// Node specific peer on my host to select yellow endpoints.
		abp.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindBGPPeer, Name: "node-specific-peer-my-host-yellow"},
				Value: &v3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-specific-peer-my-host-yellow",
					},
					Spec: v3.BGPPeerSpec{
						Node:                  "my-host",
						LocalWorkloadSelector: "color == 'yellow'",
					},
				},
			},
		})

		Expect(result["w-red"]).To(Equal("global-peer-red"))
		Expect(result["w-red-2"]).To(Equal("global-peer-red"))
		Expect(result["w-blue"]).To(Equal("node-specific-peer-my-host-blue"))
		Expect(result["w-yellow"]).To(Equal("node-specific-peer-my-host-yellow"))
	})
})
