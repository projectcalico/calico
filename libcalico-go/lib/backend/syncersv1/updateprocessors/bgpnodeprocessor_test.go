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
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the (BGP) Node update processor", func() {
	v3NodeKey1 := model.ResourceKey{
		Kind: libapiv3.KindNode,
		Name: "bgpnode1",
	}
	numBgpConfigs := 6
	up := updateprocessors.NewBGPNodeUpdateProcessor(false)

	BeforeEach(func() {
		up.OnSyncerStarting()
	})

	// The Node contains a bunch of v1 per-node BGP configuration - so we can simply use the
	// checkExpectedConfigs() function defined in the configurationprocessor_test to perform
	// our validation.  Note that it expects a node name of bgpnode1.
	It("should handle conversion of valid Nodes", func() {
		By("converting a zero-ed Node")
		res := libapiv3.NewNode()
		res.Name = "bgpnode1"
		expected := map[string]interface{}{
			"ip_addr_v4":    "",
			"ip_addr_v6":    "",
			"network_v4":    nil,
			"network_v6":    nil,
			"as_num":        nil,
			"rr_cluster_id": "",
		}
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)

		By("converting a zero-ed but non-nil BGPNodeSpec")
		res = libapiv3.NewNode()
		res.Name = "bgpnode1"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		// same expected results as the fully zeroed struct.
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)

		By("converting a Node with an IPv4 (specified without the network) only - expect /32 net")
		res = libapiv3.NewNode()
		res.Name = "bgpnode1"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "1.2.3.4",
		}
		expected = map[string]interface{}{
			"ip_addr_v4":    "1.2.3.4",
			"ip_addr_v6":    "",
			"network_v4":    "1.2.3.4/32",
			"network_v6":    nil,
			"as_num":        nil,
			"rr_cluster_id": "",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)

		By("converting a Node with an IPv6 (specified without the network) only - expect /128 net")
		res = libapiv3.NewNode()
		res.Name = "bgpnode1"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv6Address: "aa:bb:cc::",
		}
		expected = map[string]interface{}{
			"ip_addr_v4":    "",
			"ip_addr_v6":    "aa:bb:cc::",
			"network_v4":    nil,
			"network_v6":    "aa:bb:cc::/128",
			"as_num":        nil,
			"rr_cluster_id": "",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)

		By("converting a Node with IPv4 and IPv6 network and AS number")
		res = libapiv3.NewNode()
		res.Name = "bgpnode1"
		asn := numorstring.ASNumber(12345)
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "1.2.3.4/24",
			IPv6Address: "aa:bb:cc::ffff/120",
			ASNumber:    &asn,
		}
		expected = map[string]interface{}{
			"ip_addr_v4":    "1.2.3.4",
			"ip_addr_v6":    "aa:bb:cc::ffff",
			"network_v4":    "1.2.3.0/24",
			"network_v6":    "aa:bb:cc::ff00/120",
			"as_num":        "12345",
			"rr_cluster_id": "",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
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

		By("trying to convert with an invalid IPv4 address - treat as unassigned")
		res = libapiv3.NewNode()
		res.Name = "bgpnode1"
		asn := numorstring.ASNumber(12345)
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "1.2.3.4/240",
			IPv6Address: "aa:bb:cc::ffff/120",
			ASNumber:    &asn,
		}
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		// IPv4 address should be blank, network should be nil (deleted)
		expected := map[string]interface{}{
			"ip_addr_v4":    "",
			"ip_addr_v6":    "aa:bb:cc::ffff",
			"network_v4":    nil,
			"network_v6":    "aa:bb:cc::ff00/120",
			"as_num":        "12345",
			"rr_cluster_id": "",
		}
		Expect(err).To(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)

		By("trying to convert with an invalid IPv6 address - treat as unassigned")
		res = libapiv3.NewNode()
		res.Name = "bgpnode1"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address: "1.2.3.4/24",
			IPv6Address: "aazz::qq/100",
		}
		kvps, err = up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		// IPv6 address should be blank, network should be nil (deleted)
		expected = map[string]interface{}{
			"ip_addr_v4":    "1.2.3.4",
			"ip_addr_v6":    "",
			"network_v4":    "1.2.3.0/24",
			"network_v6":    nil,
			"as_num":        nil,
			"rr_cluster_id": "",
		}
		Expect(err).To(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)
	})

	It("should handle route reflector cluster ID field", func() {
		res := libapiv3.NewNode()
		res.Name = "bgpnode1"
		res.Spec.BGP = &libapiv3.NodeBGPSpec{
			IPv4Address:             "172.17.0.2/24",
			RouteReflectorClusterID: "255.0.0.1",
		}
		expected := map[string]interface{}{
			"ip_addr_v4":    "172.17.0.2",
			"ip_addr_v6":    "",
			"network_v4":    "172.17.0.0/24",
			"network_v6":    nil,
			"as_num":        nil,
			"rr_cluster_id": "255.0.0.1",
		}
		kvps, err := up.Process(&model.KVPair{
			Key:   v3NodeKey1,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeBgpConfig,
			numBgpConfigs,
			expected,
		)
	})
})

var _ = Describe("Test the (BGP) Node update processor with USE_POD_CIDR=true", func() {
	v3NodeKey1 := model.ResourceKey{
		Kind: libapiv3.KindNode,
		Name: "mynode",
	}
	up := updateprocessors.NewBGPNodeUpdateProcessor(true)

	BeforeEach(func() {
		up.OnSyncerStarting()
	})

	It("should properly convert nodes into block affinities for BGP", func() {
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
		v := model.BlockAffinity{State: model.StateConfirmed}
		assertBlockAffinityUpdate(kvps, &model.KVPair{Key: model.BlockAffinityKey{CIDR: c1, Host: "mynode"}, Value: &v})

		c2 := net.MustParseCIDR("192.168.2.0/24")
		assertBlockAffinityUpdate(kvps, &model.KVPair{Key: model.BlockAffinityKey{CIDR: c2, Host: "mynode"}, Value: &v})

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

		// Assert we get block affinity 1
		assertBlockAffinityUpdate(kvps, &model.KVPair{Key: model.BlockAffinityKey{CIDR: c1, Host: "mynode"}, Value: &v})

		// And a remove for block affinity 2.
		assertBlockAffinityUpdate(kvps, &model.KVPair{Key: model.BlockAffinityKey{CIDR: c2, Host: "mynode"}, Value: nil})
	})
})

func assertBlockAffinityUpdate(kvps []*model.KVPair, expected *model.KVPair) {
	for _, kvp := range kvps {
		switch kvp.Key.(type) {
		case model.BlockAffinityKey:
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
