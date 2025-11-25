// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.

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

package model_test

import (
	"reflect"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// interestingPaths contains seed data for the KeyFromDefaultPath fuzzer.
//
// Some of these inputs are junk (they test that bad keys are ignored and that nothing panics) and
// some are not really valid in the "global" sense.  For example, we include strings with percent
// encoding even though the objects they describe have other naming validation that should prevent
// that. The parser was intended to be generic and to support a range of possible orchestrator
// environments where we may need to be more permissive.
//
// Note: go test will run the Fuzz target as an ordinary unit test feeding in these inputs, so we don't
// need to duplicate all of these as extra UTs.
var interestingPaths = []string{
	"/calico/v1/config/foobar",
	"/calico/v1/config/foobar/bazz",
	"/calico/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint",
	"/calico/v1/host/foobar/endpoint",
	"/calico/v1/host/foobar/endpoint/biff",
	"/calico/v1/host/foobar/metadata",
	"/calico/v1/host/foobar/wireguard",
	"/calico/v1/host/foobar/config/biff/bopp",
	"/calico/v1/host/foobar/bird_ip",
	"/calico/v1/host/foobar",
	"/calico/v1/netset",
	"/calico/v1/netset/foo",
	"/calico/v1/Ready",
	"/calico/v1/Ready/garbage",
	"/calico/bgp/v1/global",
	"/calico/bgp/v1/global/peer_v4",
	"/calico/bgp/v1/global/peer_v4/name",
	"/calico/bgp/v1/global/peer_v4/name",
	"/calico/bgp/v1/global/peer_v4/10.0.0.5",
	"/calico/bgp/v1/global/peer_v4/10.0.0.5-500",
	"/calico/bgp/v1/global/peer_v6",
	"/calico/bgp/v1/global/peer_v6/name",
	"/calico/bgp/v1/host",
	"/calico/bgp/v1/host/peer_v4",
	"/calico/bgp/v1/host/peer_v4/name",
	"/calico/bgp/v1/host/peer_v6",
	"/calico/bgp/v1/host/peer_v6/name",
	"/calico/bgp/v1/host/random-node-2/peer_v6/aabb:aabb::ffff-123",
	"/calico/v1",
	"/calico/v1/ipam",
	"/calico/ipam/v2/assignment/ipv4/1.2.3.4-26",
	"/calico/ipam/v2/handle/foobar",
	"/calico/ipam/v2/handle/foobar/baz",
	"/calico/ipam/v2",
	"/calico/ipam/v2/host/foobar/ipv4/block/1.2.3.4-5",
	"calico/ipam/v2/host/0/ipv0/block/0",
	"/calico/felix/v1/host",
	"/calico/felix/v1/host/foo/endpoint/bar",
	"/calico/felix/v1/endpoint",
	"/calico/felix/v2/foo/host",
	"/calico/felix/v2//foo/host",
	"/calico/felix/v2/region-Europe/host/h1/status",
	"/calico/resources/v3/projectcalico.org/foo/bar/baz",
	// Note: using % encoding in some areas where we don't really expect it here, but the parser
	// does handle it, and it helps to prime the fuzzer.
	"/bar/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint",
	"/calico/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint",
	"/calico/resources/v3/projectcalico.org/felixconfigurations/default",
	"/calico/resources/v3/projectcalico.org/networkpolicies",
	"/calico/resources/v3/projectcalico.org/networkpolicies/default/my-network-policy",
	"/calico/resources/v3/projectcalico.org/felixconfigurations/default/my-network-policy",
	"/calico/felix/v2/region-Europe/host/h1/workload/o1/w1/endpoint/e1",
}

// FuzzKeyFromDefaultPath fuzzes KeyFromDefaultPath, makings sure it doesn't panic and comparing its
// output and behaviour with the older implementation.
//
// Note: once we're sure of the new implementation we might want to remove the old implementation
// next time we need to touch path parsing (or if the old impl panics in fuzzing, and we want to stop
// maintaining it!).  If we do that, we should keep the test so that it continues to check the new
// implementation doesn't panic with garbage input.
func FuzzKeyFromDefaultPath(f *testing.F) {
	for _, k := range interestingPaths {
		f.Add(k)
		f.Add(k[1:])
		f.Add(k + "/")
		f.Add("/" + k + "//")
		f.Add("/cluster/cluster-1" + k)
	}
	f.Fuzz(func(t *testing.T, path string) {
		// Parse with old and new, neither should panic!
		oldKey := OldKeyFromDefaultPath(path)
		newKey := KeyFromDefaultPath(path)
		if oldKey == nil {
			// Ignoring keys that the old parser couldn't handle.  The new parser is a little more permissive
			// and consistent in some areas of escaping.
			return
		}
		// If the old can parse it the new should parse it too (and get the same Key).
		if !safeKeysEqual(oldKey, newKey) {
			t.Fatalf("%q -> (new output) %v != (old output) %v", path, newKey, oldKey)
		}

		// Any key that we get out should support conversion back to a path.
		serialised, err := KeyToDefaultPath(newKey)
		if err != nil {
			t.Fatalf("Failed to reserialise %q -> %v -> %s", path, newKey, err)
		}

		// All our canonical paths start with a / but some key types are permissive to a missing leading
		// slash (for historical reasons around supporting older etcd versions).  Check that old and new
		// are equally permissive by removing the slash and parsing the key again.
		if len(path) > 0 && path[0] == '/' {
			serialised = serialised[1:]
		}
		newKey2 := KeyFromDefaultPath(serialised)
		oldKey2 := OldKeyFromDefaultPath(serialised)
		if !safeKeysEqual(newKey2, oldKey2) {
			t.Fatalf("%q -> (new output) %v != (old output) %v", serialised, newKey2, oldKey2)
		}
		if newKey2 != nil && !safeKeysEqual(newKey, newKey2) {
			t.Fatalf("%q -> %v but %q -> %v", path, newKey, serialised, newKey2)
		}
	})
}

func safeKeysEqual(a, b Key) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil) != (b == nil) {
		return false
	}

	// Due to an unfortunate historical mistake some of our keys embed non-comparable types net.IP and friends.
	if !reflect.ValueOf(a).Type().Comparable() || !reflect.ValueOf(b).Type().Comparable() {
		return reflect.DeepEqual(a, b)
	}
	return a == b
}

var _ = Describe("keys with region component", func() {
	It("should not parse workload endpoint status with wrong region", func() {
		Expect((WorkloadEndpointStatusListOptions{RegionString: "region-Asia"}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/workload/o1/w1/endpoint/e1")).To(BeNil())
	})

	It("should not parse active Felix status with wrong region", func() {
		Expect((ActiveStatusReportListOptions{RegionString: "region-Asia"}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/status")).To(BeNil())
	})

	It("should not parse last reported Felix status with wrong region", func() {
		Expect((LastStatusReportListOptions{RegionString: "region-Asia"}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/last_reported_status")).To(BeNil())
	})

	It("should parse workload endpoint status with any region", func() {
		Expect((WorkloadEndpointStatusListOptions{}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/workload/o1/w1/endpoint/e1")).To(Equal(WorkloadEndpointStatusKey{
			Hostname:       "h1",
			EndpointID:     "e1",
			WorkloadID:     "w1",
			OrchestratorID: "o1",
			RegionString:   RegionString("Europe"),
		}))
	})

	It("should parse active Felix status with any region", func() {
		Expect((ActiveStatusReportListOptions{}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/status")).To(Equal(ActiveStatusReportKey{
			Hostname:     "h1",
			RegionString: RegionString("Europe"),
		}))
	})

	It("should parse last reported Felix status with any region", func() {
		Expect((LastStatusReportListOptions{}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/last_reported_status")).To(Equal(LastStatusReportKey{
			Hostname:     "h1",
			RegionString: RegionString("Europe"),
		}))
	})

	It("should generate correct path for a Felix status key with the no-region region string", func() {
		Expect(KeyToDefaultPath(ActiveStatusReportKey{Hostname: "h1", RegionString: RegionString("")})).To(Equal("/calico/felix/v2/no-region/host/h1/status"))
	})

	It("should generate correct path for a workload status key with the no-region region string", func() {
		Expect(KeyToDefaultPath(WorkloadEndpointStatusKey{Hostname: "h1", EndpointID: "e1", WorkloadID: "w1", OrchestratorID: "o1", RegionString: RegionString("")})).To(Equal("/calico/felix/v2/no-region/host/h1/workload/o1/w1/endpoint/e1"))
	})

	It("should return error for a Felix status key with no region string", func() {
		_, err := KeyToDefaultPath(ActiveStatusReportKey{Hostname: "h1"})
		Expect(err).To(HaveOccurred())
	})

	It("should return error for a workload status key with no region string", func() {
		_, err := KeyToDefaultPath(WorkloadEndpointStatusKey{Hostname: "h1", EndpointID: "e1", WorkloadID: "w1", OrchestratorID: "o1"})
		Expect(err).To(HaveOccurred())
	})

	It("should give correct path root for ActiveStatusReportListOptions with unspecified region string", func() {
		Expect(ListOptionsToDefaultPathRoot(ActiveStatusReportListOptions{Hostname: "h1"})).To(Equal("/calico/felix/v2/"))
	})

	It("should give correct path root for LastStatusReportListOptions with unspecified region string", func() {
		Expect(ListOptionsToDefaultPathRoot(LastStatusReportListOptions{Hostname: "h1"})).To(Equal("/calico/felix/v2/"))
	})

	It("should give correct path root for WorkloadEndpointStatusListOptions with unspecified region string", func() {
		Expect(ListOptionsToDefaultPathRoot(WorkloadEndpointStatusListOptions{Hostname: "h1"})).To(Equal("/calico/felix/v2/"))
	})

	It("should give correct path root for ActiveStatusReportListOptions with valid region string", func() {
		Expect(ListOptionsToDefaultPathRoot(ActiveStatusReportListOptions{Hostname: "h1", RegionString: "region-us"})).To(Equal("/calico/felix/v2/region-us/host/h1/status"))
	})

	It("should give correct path root for LastStatusReportListOptions with valid region string", func() {
		Expect(ListOptionsToDefaultPathRoot(LastStatusReportListOptions{Hostname: "h1", RegionString: "region-us"})).To(Equal("/calico/felix/v2/region-us/host/h1/last_reported_status"))
	})

	It("should give correct path root for WorkloadEndpointStatusListOptions with valid region string", func() {
		Expect(ListOptionsToDefaultPathRoot(WorkloadEndpointStatusListOptions{Hostname: "h1", RegionString: "region-us"})).To(Equal("/calico/felix/v2/region-us/host/h1/workload"))
	})

	It("should return error for a Felix status key with invalid region string", func() {
		_, err := KeyToDefaultPath(ActiveStatusReportKey{Hostname: "h1", RegionString: "region-us/east"})
		Expect(err).To(HaveOccurred())
	})

	It("should return error for a workload status key with invalid region string", func() {
		_, err := KeyToDefaultPath(WorkloadEndpointStatusKey{Hostname: "h1", EndpointID: "e1", WorkloadID: "w1", OrchestratorID: "o1", RegionString: "region-us/east"})
		Expect(err).To(HaveOccurred())
	})
})

var _ = DescribeTable(
	"key parsing",
	func(strKey string, expected Key, shouldFail bool) {
		key := KeyFromDefaultPath(strKey)
		if shouldFail {
			Expect(key).To(BeNil())
		} else {
			Expect(key).To(Equal(expected))
			serialized, err := KeyToDefaultPath(expected)
			Expect(err).ToNot(HaveOccurred())
			Expect(serialized).To(Equal(strKey))
		}
	},
	Entry(
		"workload with a /",
		"/calico/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint",
		WorkloadEndpointKey{
			Hostname:       "foobar",
			OrchestratorID: "open/stack",
			WorkloadID:     "work/load",
			EndpointID:     "end/point",
		},
		false,
	),
	Entry(
		"host endpoint with a /",
		"/calico/v1/host/foobar/endpoint/end%2fpoint",
		HostEndpointKey{
			Hostname:   "foobar",
			EndpointID: "end/point",
		},
		false,
	),
	Entry(
		"host IP",
		"/calico/v1/host/foobar/bird_ip",
		HostIPKey{Hostname: "foobar"},
		false,
	),
	Entry(
		"IP pool",
		"/calico/v1/ipam/v4/pool/10.0.0.0-8",
		IPPoolKey{CIDR: mustParseCIDR("10.0.0.0/8")},
		false,
	),
	Entry(
		"poorly formatted IP pool",
		"/calico/v1/ipam/v4/pool/577559",
		nil,
		true,
	),
	Entry(
		"global felix config",
		"/calico/v1/config/foo",
		GlobalConfigKey{Name: "foo"},
		false,
	),
	Entry(
		"host config",
		"/calico/v1/host/hostname/config/foo",
		HostConfigKey{Hostname: "hostname", Name: "foo"},
		false,
	),
	Entry(
		"network set",
		"/calico/v1/netset/netsetname",
		NetworkSetKey{Name: "netsetname"},
		false,
	),
	Entry(
		"ready flag",
		"/calico/v1/Ready",
		ReadyFlagKey{},
		false,
	),
	Entry(
		"workload endpoint status",
		"/calico/felix/v2/region-Europe/host/h1/workload/o1/w1/endpoint/e1",
		WorkloadEndpointStatusKey{Hostname: "h1", EndpointID: "e1", RegionString: "region-Europe", WorkloadID: "w1", OrchestratorID: "o1"},
		false,
	),
	Entry(
		"Felix active status",
		"/calico/felix/v2/region-Europe/host/h1/status",
		ActiveStatusReportKey{Hostname: "h1", RegionString: "region-Europe"},
		false,
	),
	Entry(
		"Felix last reported status",
		"/calico/felix/v2/region-Europe/host/h1/last_reported_status",
		LastStatusReportKey{Hostname: "h1", RegionString: "region-Europe"},
		false,
	),
	Entry(
		"Global resource",
		"/calico/resources/v3/projectcalico.org/felixconfigurations/default",
		ResourceKey{
			Kind: "FelixConfiguration",
			Name: "default",
		},
		false,
	),
	Entry(
		"Invalid global resource",
		"/calico/resources/v3/projectcalico.org/networkpolicies",
		nil,
		true,
	),
	Entry(
		"Namespaced resource",
		"/calico/resources/v3/projectcalico.org/networkpolicies/default/my-network-policy",
		ResourceKey{
			Kind:      "NetworkPolicy",
			Namespace: "default",
			Name:      "my-network-policy",
		},
		false,
	),
	Entry(
		"Invalid namespaced resource",
		"/calico/resources/v3/projectcalico.org/felixconfigurations/default/my-network-policy",
		nil,
		true,
	),
	Entry(
		"NetworkPolicy",
		"/calico/v1/policy/NetworkPolicy/default/my-policy",
		PolicyKey{
			Kind:      "NetworkPolicy",
			Namespace: "default",
			Name:      "my-policy",
		},
		false,
	),
	Entry(
		"StagedNetworkPolicy",
		"/calico/v1/policy/StagedNetworkPolicy/default/my-staged-policy",
		PolicyKey{
			Kind:      "StagedNetworkPolicy",
			Namespace: "default",
			Name:      "my-staged-policy",
		},
		false,
	),
	Entry(
		"GlobalNetworkPolicy",
		"/calico/v1/policy/GlobalNetworkPolicy//my-global-policy",
		PolicyKey{
			Kind: "GlobalNetworkPolicy",
			Name: "my-global-policy",
		},
		false,
	),
)

// Test parsing of legacy style PolicyKey of form /calico/v1/policy/tier/<Tier>/policy/<Name>
var _ = DescribeTable(
	"key parsing (legacy keys)",
	func(strKey string, expected Key, shouldFail bool) {
		key := KeyFromDefaultPath(strKey)
		if shouldFail {
			Expect(key).To(BeNil())
		} else {
			Expect(key).To(Equal(expected))
		}
	},

	Entry(
		"Legacy NetworkPolicy",
		"/calico/v1/policy/tier/default/policy/ns%2fname",
		PolicyKey{
			Kind:      "NetworkPolicy",
			Namespace: "ns",
			Name:      "name",
		},
		false,
	),
	Entry(
		"Legacy GlobalNetworkPolicy",
		"/calico/v1/policy/tier/default/policy/name",
		PolicyKey{
			Kind: "GlobalNetworkPolicy",
			Name: "name",
		},
		false,
	),
	Entry(
		"Legacy StagedNetworkPolicy",
		"/calico/v1/policy/tier/default/policy/ns%2fstaged:name",
		PolicyKey{
			Kind:      "StagedNetworkPolicy",
			Namespace: "ns",
			Name:      "name",
		},
		false,
	),
	Entry(
		"Legacy StagedGlobalNetworkPolicy",
		"/calico/v1/policy/tier/default/policy/staged:name",
		PolicyKey{
			Kind: "StagedGlobalNetworkPolicy",
			Name: "name",
		},
		false,
	),
	Entry(
		"Legacy ClusterNetworkPolicy",
		"/calico/v1/policy/tier/default/policy/kcnp.kube-admin.name",
		PolicyKey{
			Kind: "KubernetesClusterNetworkPolicy",
			Name: "kube-admin.name",
		},
		false,
	),
	Entry(
		"Legacy KubernetesNetworkPolicy",
		"/calico/v1/policy/tier/default/policy/ns%2fknp.default.name",
		PolicyKey{
			Kind:      "KubernetesNetworkPolicy",
			Namespace: "ns",
			Name:      "name",
		},
		false,
	),
	Entry(
		"Legacy StagedKubernetesNetworkPolicy",
		"/calico/v1/policy/tier/default/policy/ns%2fstaged:knp.default.name",
		PolicyKey{
			Kind:      "StagedKubernetesNetworkPolicy",
			Namespace: "ns",
			Name:      "name",
		},
		false,
	),
)

var _ = DescribeTable(
	"value parsing",
	func(key Key, rawVal string, expectedVal interface{}) {
		val, err := ParseValue(key, []byte(rawVal))
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(expectedVal))
	},
	Entry(
		"Block affinity claims with confirmed state",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.64/26"),
			Host: "happyhost.io",
		},
		`{"state":"confirmed"}`,
		&BlockAffinity{State: StateConfirmed},
	),
	Entry(
		"Block affinity claims with pending state",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.0/26"),
			Host: "slightlyhappyhost.io",
		},
		`{"state":"pending"}`,
		&BlockAffinity{State: StatePending},
	),
	Entry(
		"Block affinity claims with pending-deletion state",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.192/26"),
			Host: "notsohappyhost.io",
		},
		`{"state":"pendingDeletion"}`,
		&BlockAffinity{State: StatePendingDeletion},
	),
	Entry(
		"Pre-3.0.7 style block affinity claims with no state i.e. empty string in value",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.128/26"),
			Host: "oldhost.io",
		},
		``,
		&BlockAffinity{},
	),
	Entry(
		"Block affinity claims with empty state {} in value",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.128/26"),
			Host: "oldhost.io",
		},
		`{}`,
		&BlockAffinity{},
	),
	Entry(
		"BGPPeer",
		ResourceKey{
			Kind: apiv3.KindBGPPeer,
			Name: "my-peer",
		},
		`{"spec":{"node": "node"}}`,
		&apiv3.BGPPeer{
			Spec: apiv3.BGPPeerSpec{
				Node: "node",
			},
		},
	),
	Entry(
		"BGPFilter",
		ResourceKey{
			Kind: apiv3.KindBGPFilter,
			Name: "my-bgp-filter",
		},
		`{"spec":{"exportV4": [{"action": "Accept", "cidr": "77.7.1.0/24", "matchOperator": "In"}, {"action": "Reject", "cidr": "77.7.2.0/24", "matchOperator": "NotEqual"}], "importV4": [{"action": "Accept", "cidr": "77.7.3.0/24", "matchOperator": "NotIn"}, {"action": "Reject", "cidr": "77.7.4.0/24", "matchOperator": "Equal"}], "exportV6": [{"action": "Accept", "cidr": "7000:1::0/64", "matchOperator": "Equal"}, {"action": "Reject", "cidr": "7000:2::0/64", "matchOperator": "NotEqual"}], "importV6": [{"action": "Accept", "cidr": "7000:3::0/64", "matchOperator": "In"}, {"action": "Reject", "cidr": "7000:4::0/64", "matchOperator": "NotIn"}]}}`,
		&apiv3.BGPFilter{
			Spec: apiv3.BGPFilterSpec{
				ExportV4: []apiv3.BGPFilterRuleV4{
					{
						Action:        apiv3.Accept,
						CIDR:          "77.7.1.0/24",
						MatchOperator: apiv3.In,
					},
					{
						Action:        apiv3.Reject,
						CIDR:          "77.7.2.0/24",
						MatchOperator: apiv3.NotEqual,
					},
				},
				ImportV4: []apiv3.BGPFilterRuleV4{
					{
						Action:        apiv3.Accept,
						CIDR:          "77.7.3.0/24",
						MatchOperator: apiv3.NotIn,
					},
					{
						Action:        apiv3.Reject,
						CIDR:          "77.7.4.0/24",
						MatchOperator: apiv3.Equal,
					},
				},
				ExportV6: []apiv3.BGPFilterRuleV6{
					{
						Action:        apiv3.Accept,
						CIDR:          "7000:1::0/64",
						MatchOperator: apiv3.Equal,
					},
					{
						Action:        apiv3.Reject,
						CIDR:          "7000:2::0/64",
						MatchOperator: apiv3.NotEqual,
					},
				},
				ImportV6: []apiv3.BGPFilterRuleV6{
					{
						Action:        apiv3.Accept,
						CIDR:          "7000:3::0/64",
						MatchOperator: apiv3.In,
					},
					{
						Action:        apiv3.Reject,
						CIDR:          "7000:4::0/64",
						MatchOperator: apiv3.NotIn,
					},
				},
			},
		},
	),
)

func mustParseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *ipNet
}

var (
	benchResult any
	_           = benchResult
	benchKeys   = []Key{
		WorkloadEndpointKey{
			Hostname:       "ip-12-23-24-52.cloud.foo.bar.baz",
			OrchestratorID: "kubernetes",
			WorkloadID:     "some-pod-name-12346",
			EndpointID:     "eth0",
		},
		WireguardKey{NodeName: "ip-12-23-24-53.cloud.foo.bar.baz"},
		HostEndpointKey{
			Hostname:   "ip-12-23-24-52.cloud.foo.bar.baz",
			EndpointID: "eth0",
		},
		ResourceKey{
			Name:      "projectcalico-default-allow",
			Namespace: "default",
			Kind:      apiv3.KindNetworkPolicy,
		},
	}
)

func BenchmarkOldKeyFromDefaultPath(b *testing.B) {
	benchmarkKeyFromDefaultPathImpl(b, OldKeyFromDefaultPath)
}

func BenchmarkKeyFromDefaultPath(b *testing.B) {
	benchmarkKeyFromDefaultPathImpl(b, KeyFromDefaultPath)
}

func benchmarkKeyFromDefaultPathImpl(b *testing.B, keyFromDefaultPath func(path string) Key) {
	var benchPaths []string
	for _, k := range benchKeys {
		p, err := KeyToDefaultPath(k)
		if err != nil {
			b.Fatal("Failed to parse keys:", err)
		}
		benchPaths = append(benchPaths, p)
	}
	defer logrus.SetLevel(logrus.GetLevel())
	logrus.SetLevel(logrus.PanicLevel)

	b.ResetTimer()
	var key any
	for i := 0; i <= b.N; i++ {
		p := benchPaths[i%len(benchPaths)]
		key = keyFromDefaultPath(p)
	}
	benchResult = key
}
