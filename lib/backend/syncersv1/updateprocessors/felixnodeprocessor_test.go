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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("Test the (Felix) Node update processor", func() {
	v3NodeKey1 := model.ResourceKey{
		Kind: apiv3.KindNode,
		Name: "mynode",
	}
	numFelixConfigs := 3
	up := updateprocessors.NewFelixNodeUpdateProcessor()

	BeforeEach(func() {
		up.OnSyncerStarting()
	})

	// The Node contains a bunch of v1 per-node Felix configuration - so we can simply use the
	// checkExpectedConfigs() function defined in the configurationprocessor_test to perform
	// our validation [with a minor hack to treat HostIP as a HostConfig type].  Note that it
	// expects a node name of mynode.
	It("should handle conversion of valid Nodes", func() {
		By("converting a zero-ed Node")
		res := apiv3.NewNode()
		res.Name = "mynode"
		expected := map[string]interface{}{
			hostIPMarker:       nil,
			"IpInIpTunnelAddr": nil,
		}
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("converting a zero-ed but non-nil BGPNodeSpec")
		res = apiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &apiv3.NodeBGPSpec{}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		// same expected results as the fully zeroed struct.
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("converting a Node with an IPv4 (specified without the network) only")
		res = apiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &apiv3.NodeBGPSpec{
			IPv4Address: "1.2.3.4",
		}
		ip := net.MustParseIP("1.2.3.4")
		expected = map[string]interface{}{
			hostIPMarker:       &ip,
			"IpInIpTunnelAddr": nil,
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("converting a Node with IPv4 and IPv6 networks and no other config")
		res = apiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &apiv3.NodeBGPSpec{
			IPv4Address: "100.200.100.200/24",
			IPv6Address: "aa:bb::cc/120",
		}
		ip = net.MustParseIP("100.200.100.200")
		expected = map[string]interface{}{
			hostIPMarker:       &ip,
			"IpInIpTunnelAddr": nil,
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("converting a Node with IPv6 networks and an IPv4 tunnel address and no other config")
		res = apiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &apiv3.NodeBGPSpec{
			IPv6Address:        "aa:bb::cc/120",
			IPv4IPIPTunnelAddr: "192.100.100.100",
		}
		expected = map[string]interface{}{
			hostIPMarker:       nil,
			"IpInIpTunnelAddr": "192.100.100.100",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)
	})

	It("should fail to convert an invalid resource", func() {
		By("trying to convert with the wrong key type")
		res := apiv3.NewNode()

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalConfigKey{
				Name: "foobar",
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv3.NewBGPPeer()
		_, err = up.Process(&model.KVPair{
			Key:      v3NodeKey1,
			Value:    wres,
			Revision: "abcdef",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with an invalid IPv4 address - expect delete for that key")
		res = apiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &apiv3.NodeBGPSpec{
			IPv4Address:        "1.2.3.4/240",
			IPv4IPIPTunnelAddr: "192.100.100.100",
		}
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).To(HaveOccurred())
		expected := map[string]interface{}{
			hostIPMarker:       nil,
			"IpInIpTunnelAddr": "192.100.100.100",
		}
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("trying to convert with a tunnel address specified as a network - expect delete for that key")
		res = apiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &apiv3.NodeBGPSpec{
			IPv4Address:        "1.2.3.4/24",
			IPv4IPIPTunnelAddr: "192.100.100.100/24",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).To(HaveOccurred())
		ip := net.MustParseIP("1.2.3.4")
		expected = map[string]interface{}{
			hostIPMarker:       &ip,
			"IpInIpTunnelAddr": nil,
		}
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)
	})
})
