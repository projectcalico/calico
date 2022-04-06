// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the (Felix) Node update processor", func() {
	v3NodeKey1 := model.ResourceKey{
		Kind: libapiv3.KindNode,
		Name: "mynode",
	}
	numFelixConfigs := 8
	up := updateprocessors.NewFelixNodeUpdateProcessor(false)

	BeforeEach(func() {
		up.OnSyncerStarting()
	})

	// The Node contains a bunch of v1 per-node Felix configuration - so we can simply use the
	// checkExpectedConfigs() function defined in the configurationprocessor_test to perform
	// our validation [with a minor hack to treat HostIP as a HostConfig type].  Note that it
	// expects a node name of mynode.
	It("should handle conversion of valid Nodes", func() {
		By("converting a zero-ed Node")
		res := libapiv3.NewNode()
		res.Name = "mynode"
		expected := map[string]interface{}{
			hostIPMarker:       nil,
			nodeMarker:         res,
			"IpInIpTunnelAddr": nil,
			wireguardMarker:    nil,
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
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{}
		expected[nodeMarker] = res
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

		By("converting a zero-ed but non-nil WireguardSpec")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.Wireguard = &libapiv3.NodeWireguardSpec{}
		expected[nodeMarker] = res
		expected[wireguardMarker] = nil
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
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "1.2.3.4",
		}
		ip := net.MustParseIP("1.2.3.4")
		expected = map[string]interface{}{
			hostIPMarker:       &ip,
			nodeMarker:         res,
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

		By("converting a Node with Wireguard interface IPv4 address")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.Wireguard = &libapiv3.NodeWireguardSpec{
			InterfaceIPv4Address: "1.2.3.4",
		}
		expected = map[string]interface{}{
			nodeMarker: res,
			wireguardMarker: &model.Wireguard{
				InterfaceIPv4Addr: &ip,
			},
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

		By("converting a Node with Wireguard public-key")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		key := "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="
		res.Status = libapiv3.NodeStatus{
			WireguardPublicKey: key,
		}
		expected = map[string]interface{}{
			nodeMarker: res,
			wireguardMarker: &model.Wireguard{
				PublicKey: key,
			},
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

		By("converting a Node with Wireguard interface address and public-key")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.Wireguard = &libapiv3.NodeWireguardSpec{
			InterfaceIPv4Address: "1.2.3.4",
		}
		res.Status = libapiv3.NodeStatus{
			WireguardPublicKey: key,
		}
		expected = map[string]interface{}{
			nodeMarker: res,
			wireguardMarker: &model.Wireguard{
				InterfaceIPv4Addr: &ip,
				PublicKey:         key,
			},
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
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "100.200.100.200/24",
			IPv6Address: "aa:bb::cc/120",
		}
		ip = net.MustParseIP("100.200.100.200")
		expected = map[string]interface{}{
			hostIPMarker:       &ip,
			nodeMarker:         res,
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
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv6Address:        "aa:bb::cc/120",
			IPv4IPIPTunnelAddr: "192.100.100.100",
		}
		expected = map[string]interface{}{
			hostIPMarker:       nil,
			nodeMarker:         res,
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

		By("converting a Node with IPv4 address and an IPv4 VXLAN tunnel address and MAC")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "192.100.100.100",
		}
		res.Spec.IPv4VXLANTunnelAddr = "192.200.200.200"
		res.Spec.VXLANTunnelMACAddr = "00:11:22:33:44:55"
		ip = net.MustParseIP("192.100.100.100")
		expected = map[string]interface{}{
			hostIPMarker:          &ip,
			nodeMarker:            res,
			"IPv4VXLANTunnelAddr": "192.200.200.200",
			"VXLANTunnelMACAddr":  "00:11:22:33:44:55",
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

		By("converting a Node with IPv6 address and an IPv6 VXLAN tunnel address and MAC")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv6Address: "fd10:10::10",
		}
		res.Spec.IPv6VXLANTunnelAddr = "fd10:11::11"
		res.Spec.IPv6VXLANTunnelMACAddr = "55:44:33:22:11:00"
		expected = map[string]interface{}{
			hostIPMarker:             nil,
			nodeMarker:               res,
			"IPv6VXLANTunnelAddr":    "fd10:11::11",
			"IPv6VXLANTunnelMACAddr": "55:44:33:22:11:00",
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

		By("converting a Node with both IPv4 and IPv6 addresses and both IPv4 and IPv6 VXLAN tunnel addresses and MACs")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "192.100.100.100",
			IPv6Address: "fd10:10::10",
		}
		res.Spec.IPv4VXLANTunnelAddr = "192.200.200.200"
		res.Spec.VXLANTunnelMACAddr = "00:11:22:33:44:55"
		res.Spec.IPv6VXLANTunnelAddr = "fd10:11::11"
		res.Spec.IPv6VXLANTunnelMACAddr = "55:44:33:22:11:00"
		ip = net.MustParseIP("192.100.100.100")
		expected = map[string]interface{}{
			hostIPMarker:             &ip,
			nodeMarker:               res,
			"IPv4VXLANTunnelAddr":    "192.200.200.200",
			"VXLANTunnelMACAddr":     "00:11:22:33:44:55",
			"IPv6VXLANTunnelAddr":    "fd10:11::11",
			"IPv6VXLANTunnelMACAddr": "55:44:33:22:11:00",
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
		res := libapiv3.NewNode()

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
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
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
			nodeMarker:         res,
			"IpInIpTunnelAddr": "192.100.100.100",
		}
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("trying to convert with an invalid Wireguard interface IPv4 address - expect delete for that key")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.Wireguard = &libapiv3.NodeWireguardSpec{
			InterfaceIPv4Address: "1.2.3.4/240",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).To(HaveOccurred())
		expected = map[string]interface{}{
			nodeMarker:      res,
			wireguardMarker: nil,
		}
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("trying to convert with a tunnel address specified as a network - expect delete for that key")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
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
			nodeMarker:         res,
			"IpInIpTunnelAddr": nil,
		}
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("trying to convert a Node with IPv4 address as a network and an IPv4 VXLAN tunnel address as a network and no MAC - expect delete for those keys")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "192.100.100.100/24",
		}
		res.Spec.IPv4VXLANTunnelAddr = "192.200.200.200/32"
		res.Spec.VXLANTunnelMACAddr = ""
		ip = net.MustParseIP("192.100.100.100")
		expected = map[string]interface{}{
			hostIPMarker:          &ip,
			nodeMarker:            res,
			"IPv4VXLANTunnelAddr": nil,
			"VXLANTunnelMACAddr":  nil,
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).To(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("trying to convert a Node with IPv6 address as a network and an IPv6 VXLAN tunnel address as a network and no MAC - expect delete for those keys")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv6Address: "fd10:10::10/122",
		}
		res.Spec.IPv6VXLANTunnelAddr = "fd10:11::11/122"
		res.Spec.IPv6VXLANTunnelMACAddr = ""
		expected = map[string]interface{}{
			hostIPMarker:             nil,
			nodeMarker:               res,
			"IPv6VXLANTunnelAddr":    nil,
			"IPv6VXLANTunnelMACAddr": nil,
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).To(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)

		By("trying to convert a Node with both IPv4 and IPv6 addresses as networks and both IPv4 and IPv6 VXLAN tunnel addresses as networks and no MACs - expect delete for those keys")
		res = libapiv3.NewNode()
		res.Name = "mynode"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "192.100.100.100/24",
			IPv6Address: "fd10:10::10/122",
		}
		res.Spec.IPv4VXLANTunnelAddr = "192.200.200.200/24"
		res.Spec.VXLANTunnelMACAddr = ""
		res.Spec.IPv6VXLANTunnelAddr = "fd10:11::11/112"
		res.Spec.IPv6VXLANTunnelMACAddr = ""
		ip = net.MustParseIP("192.100.100.100")
		expected = map[string]interface{}{
			hostIPMarker:             &ip,
			nodeMarker:               res,
			"IPv4VXLANTunnelAddr":    nil,
			"VXLANTunnelMACAddr":     nil,
			"IPv6VXLANTunnelAddr":    nil,
			"IPv6VXLANTunnelMACAddr": nil,
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).To(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			expected,
		)
	})
})

var _ = Describe("Test the (Felix) Node update processor with USE_POD_CIDR=true", func() {
	v3NodeKey1 := model.ResourceKey{
		Kind: libapiv3.KindNode,
		Name: "mynode",
	}
	up := updateprocessors.NewFelixNodeUpdateProcessor(true)

	BeforeEach(func() {
		up.OnSyncerStarting()
	})

	It("should contain updates with nil values for a delete", func() {
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		for i := range kvps {
			Expect(kvps[i].Value == nil).To(BeTrue(), kvps[i].Key.String())
		}
	})

	It("should properly convert nodes into blocks for Felix", func() {
		By("converting a node with PodCIDRs set")
		res := libapiv3.NewNode()
		res.Name = "mynode"
		res.Status.PodCIDRs = []string{
			"192.168.1.0/24",
			"192.168.2.0/24",
		}

		// Process it.
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure we have the correct KVP updates - one for each CIDR.
		c1 := net.MustParseCIDR("192.168.1.0/24")
		aff := "host:mynode"
		v1 := model.AllocationBlock{CIDR: c1, Affinity: &aff}
		assertBlockUpdate(kvps, &model.KVPair{Key: model.BlockKey{CIDR: c1}, Value: &v1})

		c2 := net.MustParseCIDR("192.168.2.0/24")
		v2 := model.AllocationBlock{CIDR: c2, Affinity: &aff}
		assertBlockUpdate(kvps, &model.KVPair{Key: model.BlockKey{CIDR: c2}, Value: &v2})

		// Remove CIDR 2 and make sure we get a delete for it.
		By("handling an update that removes a CIDR")
		res.Status.PodCIDRs = []string{
			"192.168.1.0/24",
		}

		// Process it.
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())

		// Assert we get block 1
		assertBlockUpdate(kvps, &model.KVPair{Key: model.BlockKey{CIDR: c1}, Value: &v1})

		// And a remove for block 2.
		assertBlockUpdate(kvps, &model.KVPair{Key: model.BlockKey{CIDR: c2}, Value: nil})
	})
})

func assertBlockUpdate(kvps []*model.KVPair, expected *model.KVPair) {
	for _, kvp := range kvps {
		switch kvp.Key.(type) {
		case model.BlockKey:
			if reflect.DeepEqual(kvp.Key, expected.Key) {
				if expected.Value == nil {
					Expect(kvp.Value).To(BeNil())
				} else {
					Expect(kvp.Value).To(Equal(expected.Value))
				}
				return
			}
		}
	}

	// Build a nice error message.
	e := fmt.Sprintf("%v \n\nnot found in\n\n [", expected)
	for _, k := range kvps {
		e = fmt.Sprintf("%s\n%#v", e, *k)

	}
	e += "]"
	Expect(fmt.Errorf(e)).NotTo(HaveOccurred())
}
