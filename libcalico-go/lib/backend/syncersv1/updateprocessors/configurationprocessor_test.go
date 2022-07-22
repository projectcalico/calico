// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	// What the expected sync datatypes are.
	isGlobalFelixConfig = iota
	isNodeFelixConfig
	isGlobalBgpConfig
	isNodeBgpConfig

	hostIPMarker    = "*HOSTIP*"
	nodeMarker      = "*NODEMARKER*"
	wireguardMarker = "*WIREGUARDMARKER*"
)

const (
	numBaseFelixConfigs = 118
)

var _ = Describe("Test the generic configuration update processor and the concrete implementations", func() {
	// Define some common values
	perNodeFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "node.mynode",
	}
	globalFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "default",
	}
	invalidFelixKey := model.ResourceKey{
		Kind: apiv3.KindFelixConfiguration,
		Name: "foobar",
	}
	globalClusterKey := model.ResourceKey{
		Kind: apiv3.KindClusterInformation,
		Name: "default",
	}
	nodeClusterKey := model.ResourceKey{
		Kind: apiv3.KindClusterInformation,
		Name: "node.mynode",
	}
	numFelixConfigs := numBaseFelixConfigs
	numClusterConfigs := 5
	numNodeClusterConfigs := 4
	felixMappedNames := map[string]interface{}{
		"RouteRefreshInterval":               nil,
		"IptablesRefreshInterval":            nil,
		"IpsetsRefreshInterval":              nil,
		"IpInIpEnabled":                      nil,
		"IpInIpMtu":                          nil,
		"IptablesNATOutgoingInterfaceFilter": nil,
	}

	It("should handle conversion of node-specific delete with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("converting a per-node felix key and checking for the correct number of fields")
		kvps, err := cc.Process(&model.KVPair{
			Key: perNodeFelixKey,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(kvps, isNodeFelixConfig, numFelixConfigs, felixMappedNames)
	})

	It("should handle conversion of global delete with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("converting a global felix key and checking for the correct number of fields")
		kvps, err := cc.Process(&model.KVPair{
			Key: globalFelixKey,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(kvps, isGlobalFelixConfig, numFelixConfigs, felixMappedNames)
	})

	It("should handle conversion of node-specific zero value KVPairs with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err := cc.Process(&model.KVPair{
			Key:   perNodeFelixKey,
			Value: apiv3.NewFelixConfiguration(),
		})
		Expect(err).NotTo(HaveOccurred())
		// Explicitly pass in the "mapped" name values to check to ensure the names are mapped.
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numFelixConfigs,
			felixMappedNames,
		)
	})

	It("should handle conversion of global zero value KVPairs with no additional configs", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: apiv3.NewFelixConfiguration(),
		})
		Expect(err).NotTo(HaveOccurred())
		// Explicitly pass in the "mapped" name values to check to ensure the names are mapped.
		checkExpectedConfigs(
			kvps,
			isGlobalFelixConfig,
			numFelixConfigs,
			felixMappedNames,
		)
	})

	It("should gracefully handle invalid names/keys/types/values", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("Testing invalid Key on ProcessDeleted")
		_, err := cc.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
		})
		Expect(err).To(HaveOccurred())

		By("Testing invalid Key on Process")
		_, err = cc.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value: apiv3.NewFelixConfiguration(),
		})
		Expect(err).To(HaveOccurred())

		By("Testing non-resource type value on Process with add/mod")
		_, err = cc.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: "this isn't a resource",
		})
		Expect(err).To(HaveOccurred())

		By("Testing incorrect resource type value on Process with add/mod")
		_, err = cc.Process(&model.KVPair{
			Key:   globalFelixKey,
			Value: libapiv3.NewWorkloadEndpoint(),
		})
		Expect(err).To(HaveOccurred())

		By("Testing incorrect name structure on Process with add/mod")
		_, err = cc.Process(&model.KVPair{
			Key:   invalidFelixKey,
			Value: apiv3.NewFelixConfiguration(),
		})
		Expect(err).To(HaveOccurred())

		By("Testing incorrect name structure on Process with delete")
		_, err = cc.Process(&model.KVPair{
			Key: invalidFelixKey,
		})
		Expect(err).To(HaveOccurred())
	})

	It("should handle different field types being assigned", func() {
		cc := updateprocessors.NewFelixConfigUpdateProcessor()
		By("converting a per-node felix KVPair with certain values and checking for the correct number of fields")
		res := apiv3.NewFelixConfiguration()
		duration1 := metav1.Duration{Duration: time.Duration(12.345 * float64(time.Second))}
		duration2 := metav1.Duration{Duration: time.Duration(54.321 * float64(time.Millisecond))}
		duration3 := metav1.Duration{Duration: time.Duration(0)}
		duration4 := metav1.Duration{Duration: time.Duration(0.1 * float64(time.Second))}
		bool1 := false
		uint1 := uint32(1313)
		res.Spec.RouteRefreshInterval = &duration1
		res.Spec.IptablesLockProbeInterval = &duration2
		res.Spec.EndpointReportingDelay = &duration3
		res.Spec.IpsetsRefreshInterval = &duration4
		res.Spec.InterfacePrefix = "califoobar"
		res.Spec.IPIPEnabled = &bool1
		res.Spec.IptablesMarkMask = &uint1
		res.Spec.FailsafeInboundHostPorts = &[]apiv3.ProtoPort{}
		res.Spec.FailsafeOutboundHostPorts = &[]apiv3.ProtoPort{
			{
				Protocol: "TCP",
				Port:     1234,
				Net:      "0.0.0.0/0",
			},
			{
				Protocol: "UDP",
				Port:     22,
				Net:      "0.0.0.0/0",
			},
			{
				Protocol: "TCP",
				Port:     65535,
				Net:      "0.0.0.0/0",
			},
		}
		res.Spec.ExternalNodesCIDRList = &[]string{"1.1.1.1", "2.2.2.2"}
		res.Spec.IptablesNATOutgoingInterfaceFilter = "cali-123"
		res.Spec.RouteTableRanges = &apiv3.RouteTableRanges{{Min: 43, Max: 211}}
		expected := map[string]interface{}{
			"RouteRefreshInterval":               "12.345",
			"IptablesLockProbeIntervalMillis":    "54.321",
			"EndpointReportingDelaySecs":         "0",
			"IpsetsRefreshInterval":              "0.1",
			"InterfacePrefix":                    "califoobar",
			"IpInIpEnabled":                      "false",
			"IptablesMarkMask":                   "1313",
			"FailsafeInboundHostPorts":           "none",
			"FailsafeOutboundHostPorts":          "tcp:0.0.0.0/0:1234,udp:0.0.0.0/0:22,tcp:0.0.0.0/0:65535",
			"ExternalNodesCIDRList":              "1.1.1.1,2.2.2.2",
			"IptablesNATOutgoingInterfaceFilter": "cali-123",
			"RouteTableRanges":                   "43-211",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   perNodeFelixKey,
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

	It("should handle cluster config string slice field", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		By("converting a global cluster info KVPair with values assigned")
		res := apiv3.NewClusterInformation()
		res.Spec.ClusterGUID = "abcedfg"
		res.Spec.ClusterType = "Mesos,K8s"
		expected := map[string]interface{}{
			"ClusterGUID": "abcedfg",
			"ClusterType": "Mesos,K8s",
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalFelixConfig,
			numClusterConfigs,
			expected,
		)
	})

	It("should handle cluster config ready flag field", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		By("converting a global cluster info KVPair with values assigned")
		res := apiv3.NewClusterInformation()
		ready := true
		res.Spec.DatastoreReady = &ready
		expected := map[string]interface{}{
			"ready-flag": true,
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalFelixConfig,
			numClusterConfigs,
			expected,
		)
	})

	It("should handle cluster config ready flag field (false)", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		By("converting a global cluster info KVPair with values assigned")
		res := apiv3.NewClusterInformation()
		ready := false
		res.Spec.DatastoreReady = &ready
		expected := map[string]interface{}{
			"ready-flag": false,
		}
		kvps, err := cc.Process(&model.KVPair{
			Key:   globalClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isGlobalFelixConfig,
			numClusterConfigs,
			expected,
		)
	})

	It("should handle node cluster information", func() {
		cc := updateprocessors.NewClusterInfoUpdateProcessor()
		res := apiv3.NewClusterInformation()

		By("validating an empty per node cluster is processed correctly")
		kvps, err := cc.Process(&model.KVPair{
			Key:   nodeClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numNodeClusterConfigs,
			nil,
		)

		By("validating it is not possible to set/override values using the annotations")
		res.Annotations = map[string]string{
			"config.projectcalico.org/ClusterType": "this is not validated!",
			"config.projectcalico.org/NewField":    "this is also not validated!",
		}
		kvps, err = cc.Process(&model.KVPair{
			Key:   nodeClusterKey,
			Value: res,
		})
		Expect(err).NotTo(HaveOccurred())
		checkExpectedConfigs(
			kvps,
			isNodeFelixConfig,
			numNodeClusterConfigs,
			nil,
		)
	})
})

// Check the KVPairs returned by the UpdateProcessor are as expected.  The expectedValues contains
// the expected set of data in the updates, any config not specified in the set is expected
// to be nil in the KVPair.
// You can use expectedValues to verify certain fields were included in the response even
// if the values were nil.
func checkExpectedConfigs(kvps []*model.KVPair, dataType int, expectedNum int, expectedValues map[string]interface{}) {
	// Copy/convert input data.  We keep track of:
	// - all field names, so that we can check for duplicates
	// - extra fields that we have not yet seen
	// - expected field values that we have not yet validated
	ev := make(map[string]interface{}, len(expectedValues))
	for k, v := range expectedValues {
		ev[k] = v
	}
	allNames := map[string]struct{}{}

	By(" - checking the expected number of results")
	Expect(kvps).To(HaveLen(expectedNum))

	By(" - checking for duplicated, nil values and assigned values as expected")
	for _, kvp := range kvps {
		var name string
		switch dataType {
		case isGlobalFelixConfig:
			switch kvp.Key.(type) {
			case model.ReadyFlagKey:
				name = "ready-flag"
			default:
				ExpectWithOffset(1, kvp.Key).To(BeAssignableToTypeOf(model.GlobalConfigKey{}))
				name = kvp.Key.(model.GlobalConfigKey).Name
			}
		case isNodeFelixConfig:
			switch kt := kvp.Key.(type) {
			case model.HostConfigKey:
				node := kt.Hostname
				ExpectWithOffset(1, node).To(Equal("mynode"))
				name = kt.Name
			case model.HostIPKey:
				// Although the HostIPKey is not in the same key space as the HostConfig, we
				// special case this to make this test reusable for more tests.
				node := kt.Hostname
				ExpectWithOffset(1, node).To(Equal("mynode"))
				name = hostIPMarker
				logrus.Warnf("IP in key: %s", kvp.Value)
			case model.ResourceKey:
				node := kt.Name
				ExpectWithOffset(1, node).To(Equal("mynode"))
				name = nodeMarker
			case model.WireguardKey:
				node := kt.NodeName
				ExpectWithOffset(1, node).To(Equal("mynode"))
				name = wireguardMarker
			default:
				ExpectWithOffset(1, kvp.Key).To(BeAssignableToTypeOf(model.HostConfigKey{}))
			}
		case isGlobalBgpConfig:
			ExpectWithOffset(1, kvp.Key).To(BeAssignableToTypeOf(model.GlobalBGPConfigKey{}))
			name = kvp.Key.(model.GlobalBGPConfigKey).Name
		case isNodeBgpConfig:
			ExpectWithOffset(1, kvp.Key).To(BeAssignableToTypeOf(model.NodeBGPConfigKey{}))
			node := kvp.Key.(model.NodeBGPConfigKey).Nodename
			ExpectWithOffset(1, node).To(Equal("bgpnode1"))
			name = kvp.Key.(model.NodeBGPConfigKey).Name
		}

		// Validate and track the expected values.
		if v, ok := ev[name]; ok {
			if v == nil {
				ExpectWithOffset(1, kvp.Value).To(BeNil(), "Field: "+name)
			} else {
				ExpectWithOffset(1, kvp.Value).To(Equal(v), "Field: "+name)
			}
			delete(ev, name)
		} else {
			ExpectWithOffset(1, kvp.Value).To(BeNil(), "Field: "+name)
		}

		// Validate the fields we have seen, checking for duplicates.
		_, ok := allNames[name]
		ExpectWithOffset(1, ok).To(BeFalse(), fmt.Sprintf("config name is repeated in response: %s", name))
		allNames[name] = struct{}{}
	}

	By(" - checking all expected values were accounted for")
	ExpectWithOffset(1, ev).To(HaveLen(0), fmt.Sprintf("config name missing in response"))
}
