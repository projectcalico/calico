// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

package calc_test

import (
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = DescribeTable("Check Inserting CIDR and compare with network set names",
	func(key model.NetworkSetKey, netset *model.NetworkSet) {
		it := NewIpTrie()

		for _, cidr := range netset.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			it.InsertKey(cidrb, key)
		}
		for _, cidr := range netset.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			keys, ok := it.GetKeys(cidrb)
			for _, ekey := range keys {
				Expect(ok).To(Equal(true))
				Expect(ekey).To(Equal(key))
			}
		}
	},
	Entry("Insert network CIDR and match with ns name", netSet1Key, &netSet1),
	Entry("Insert network CIDR and match with ns name", netSet2Key, &netSet2),
)

var _ = DescribeTable("Insert and Delete CIDRs and compare with network set names",
	func(key model.NetworkSetKey, netset *model.NetworkSet, key1 model.NetworkSetKey, netset1 *model.NetworkSet) {
		it := NewIpTrie()

		for _, cidr := range netset1.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			it.InsertKey(cidrb, key1)
		}
		for _, cidr := range netset.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			it.InsertKey(cidrb, key)
		}
		for _, cidr := range netset1.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			it.DeleteKey(cidrb, key1)
		}
		for _, cidr := range netset.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			keys, ok := it.GetKeys(cidrb)
			for _, ekey := range keys {
				Expect(ok).To(Equal(true))
				Expect(ekey).To(Equal(key))
			}
		}
	},
	Entry("Insert network CIDR and match with ns name", netSet1Key, &netSet1, netSet2Key, &netSet2),
	Entry("Insert network CIDR and match with ns name", netSet2Key, &netSet2, netSet1Key, &netSet1),
)

var _ = DescribeTable("Test by finding Longest Prefix Match CIDR's name for given IP Address",
	func(key1 model.NetworkSetKey, key2 model.NetworkSetKey, netset1 *model.NetworkSet, netset2 *model.NetworkSet, ipAddr net.IP, res model.NetworkSetKey) {
		it := NewIpTrie()
		ipaddr := ip.FromNetIP(ipAddr)

		for _, cidr := range netset1.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			it.InsertKey(cidrb, key1)
		}
		for _, cidr := range netset2.Nets {
			cidrb := ip.CIDRFromCalicoNet(cidr)
			it.InsertKey(cidrb, key2)
		}

		key, ok := it.GetLongestPrefixCidr(ipaddr)
		Expect(ok).To(Equal(true))
		Expect(key).To(Equal(res))
	},
	Entry("Longest Prefix Match find ns name", netSet1Key, netSet3Key, &netSet1, &netSet3, netset3Ip1a, netSet1Key),
	Entry("Longest Prefix Match find ns name", netSet1Key, netSet3Key, &netSet1, &netSet3, netset3Ip1b, netSet3Key),
)

var _ = Describe("IpTrie Namespace-Aware Functionality", func() {
	var it *IpTrie
	var ns1Key, ns2Key, globalKey model.NetworkSetKey
	var testCIDR ip.CIDR
	var testIP ip.Addr

	BeforeEach(func() {
		it = NewIpTrie()

		// Create test keys with different namespaces
		ns1Key = model.NetworkSetKey{Name: "namespace1/test-netset"}
		ns2Key = model.NetworkSetKey{Name: "namespace2/test-netset"}
		globalKey = model.NetworkSetKey{Name: "global-netset"}

		// Create test CIDR and IP
		testCIDR = ip.MustParseCIDROrIP("10.0.0.0/24")
		testIP = ip.FromNetIP(mustParseIP("10.0.0.100").IP)
	})

	Context("when testing namespace-aware insertion and retrieval", func() {
		It("should organize keys by namespace correctly", func() {
			// Insert keys from different namespaces for the same CIDR
			it.InsertKey(testCIDR, globalKey)
			it.InsertKey(testCIDR, ns1Key)
			it.InsertKey(testCIDR, ns2Key)

			// Test namespace-specific retrieval
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns1Key))

			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace2")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns2Key))

			// Test fallback to global when namespace not found
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey))
		})

		It("should use lexicographic tie-breaking for same namespace", func() {
			// Insert two keys in the same namespace for the same CIDR
			firstKey := model.NetworkSetKey{Name: "namespace1/first-netset"}
			secondKey := model.NetworkSetKey{Name: "namespace1/second-netset"}

			it.InsertKey(testCIDR, firstKey)
			it.InsertKey(testCIDR, secondKey)

			// Should return the lexicographically smallest key
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(firstKey)) // "first-netset" < "second-netset"
		})

		It("should return the namespace that matches the target IP", func() {
			testIP2 := ip.FromNetIP(mustParseIP("192.168.0.100").IP)

			// Insert keys with overlapping CIDRs in different namespaces
			ns1CIDR := ip.MustParseCIDROrIP("10.0.0.0/24")
			ns2CIDR := ip.MustParseCIDROrIP("192.168.0.0/24")
			it.InsertKey(ns1CIDR, ns1Key)
			it.InsertKey(ns2CIDR, ns2Key)

			// Test that the correct namespace is returned based on the IP
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns1Key))

			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP2, "namespace2")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns2Key))
		})

		It("should fallback to other namespaces when preferred namespace is empty", func() {
			nsKey := model.NetworkSetKey{Name: "namespace1/alpha-netset"}
			otherNsKey := model.NetworkSetKey{Name: "namespace2/beta-netset"}

			it.InsertKey(testCIDR, nsKey)
			it.InsertKey(testCIDR, otherNsKey)

			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(nsKey))
		})
	})

	Context("when testing backward compatibility", func() {
		It("should work with legacy NetworkSetKey", func() {
			legacyKey := netSet1Key // This is a NetworkSetKey from test data
			it.InsertKey(testCIDR, legacyKey)

			// Should work with legacy method
			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(legacyKey))

			// Should also work with namespace method (treats as global)
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "any-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(legacyKey))
		})

		It("should maintain allKeys for backward compatibility", func() {
			it.InsertKey(testCIDR, globalKey)
			it.InsertKey(testCIDR, ns1Key)

			// GetKeys should return all keys
			keys, found := it.GetKeys(testCIDR)
			Expect(found).To(BeTrue())
			Expect(keys).To(ContainElement(globalKey))
			Expect(keys).To(ContainElement(ns1Key))
		})
	})

	Context("when testing deletion", func() {
		BeforeEach(func() {
			it.InsertKey(testCIDR, globalKey)
			it.InsertKey(testCIDR, ns1Key)
			it.InsertKey(testCIDR, ns2Key)
		})

		It("should remove keys correctly from namespace buckets", func() {
			// Delete namespace1 key
			it.DeleteKey(testCIDR, ns1Key)

			// Should no longer find namespace1 key
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey)) // Should fallback to global

			// Should still find namespace2 key
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace2")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns2Key))
		})

		It("should remove entire node when no keys remain", func() {
			// Delete all keys
			it.DeleteKey(testCIDR, globalKey)
			it.DeleteKey(testCIDR, ns1Key)
			it.DeleteKey(testCIDR, ns2Key)

			// Should not find anything
			_, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeFalse())

			_, found = it.GetKeys(testCIDR)
			Expect(found).To(BeFalse())
		})
	})

	Context("when testing edge cases", func() {
		It("should handle empty namespace correctly", func() {
			emptyNsKey := model.NetworkSetKey{Name: "empty-ns"}
			it.InsertKey(testCIDR, emptyNsKey)

			// Should be treated as global
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "any-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(emptyNsKey))
		})

		It("should handle non-existent CIDR gracefully", func() {
			nonExistentIP := ip.FromNetIP(mustParseIP("192.168.1.1").IP)

			_, found := it.GetLongestPrefixCidrWithNamespaceIsolation(nonExistentIP, "namespace1")
			Expect(found).To(BeFalse())
		})

		It("should handle unknown key types", func() {
			unknownKey := model.PolicyKey{Name: "test-policy"}
			it.InsertKey(testCIDR, unknownKey)

			// Should not be found since key type is unexpected
			_, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "any-namespace")
			Expect(found).To(BeFalse())
		})

		It("should handle 0.0.0.0/0 correctly", func() {
			zeroCIDR := ip.MustParseCIDROrIP("0.0.0.0/0")
			key := model.NetworkSetKey{Name: "zero-netset"}

			it.InsertKey(zeroCIDR, key)

			// Test with an arbitrary IP
			testIP := ip.FromNetIP(net.ParseIP("1.2.3.4"))

			foundKey, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue(), "Should find key for 0.0.0.0/0")
			Expect(foundKey).To(Equal(key))
		})
	})

	Context("when testing multiple overlapping CIDRs", func() {
		var broadCIDR, narrowCIDR ip.CIDR
		var testIPInBoth, testIPInNarrowOnly ip.Addr

		BeforeEach(func() {
			// Create overlapping CIDRs
			broadCIDR = ip.MustParseCIDROrIP("10.0.0.0/16")
			narrowCIDR = ip.MustParseCIDROrIP("10.0.1.0/24")

			// IP that matches both CIDRs
			testIPInBoth = ip.FromNetIP(mustParseIP("10.0.1.100").IP)
			// IP that matches only broad CIDR
			testIPInNarrowOnly = ip.FromNetIP(mustParseIP("10.0.2.100").IP)
		})

		It("should prioritize namespace isolation over longest prefix match", func() {
			// Insert keys for both CIDRs
			broadNs1Key := model.NetworkSetKey{Name: "namespace1/broad"}
			narrowNs2Key := model.NetworkSetKey{Name: "namespace2/narrow"}

			it.InsertKey(broadCIDR, broadNs1Key)
			it.InsertKey(narrowCIDR, narrowNs2Key)

			// For IP in both: should prefer namespace match over longer prefix
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIPInBoth, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(broadNs1Key)) // Namespace1 key wins due to namespace isolation

			// For IP in narrow only: should prefer namespace2 match when requesting namespace2
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIPInBoth, "namespace2")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(narrowNs2Key)) // Namespace2 key wins due to namespace isolation

			// For IP in broad only: should return broad CIDR
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIPInNarrowOnly, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(broadNs1Key))
		})

		It("should follow three-tier priority: namespace > global > other namespace", func() {
			// Create a more specific test scenario with all three types of keys
			testCIDR := ip.MustParseCIDROrIP("10.0.1.0/24")
			testIP := ip.FromNetIP(mustParseIP("10.0.1.100").IP)

			// Insert keys with different priorities - all matching the same CIDR
			preferredNsKey := model.NetworkSetKey{Name: "target-namespace/preferred"}
			globalKey := model.NetworkSetKey{Name: "global-netset"}
			otherNsKey := model.NetworkSetKey{Name: "other-namespace/fallback"}

			it.InsertKey(testCIDR, preferredNsKey)
			it.InsertKey(testCIDR, globalKey)
			it.InsertKey(testCIDR, otherNsKey)

			// Test 1: When preferred namespace exists, it should win
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "target-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(preferredNsKey))

			// Test 2: When preferred namespace doesn't exist, global should win over other namespace
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey))

			// Test 3: When neither preferred nor global exists, other namespace should be returned
			it2 := NewIpTrie()
			it2.InsertKey(testCIDR, otherNsKey)

			key, found = it2.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(otherNsKey))
		})

		It("should respect priority even with different prefix lengths", func() {
			// Create test scenario where global has longer prefix than preferred namespace
			broadCIDR := ip.MustParseCIDROrIP("10.0.0.0/16")     // Less specific
			narrowCIDR := ip.MustParseCIDROrIP("10.0.1.0/24")    // More specific
			testIP := ip.FromNetIP(mustParseIP("10.0.1.100").IP) // Matches both

			// Preferred namespace has broader CIDR, global has narrower CIDR
			preferredNsKey := model.NetworkSetKey{Name: "target-namespace/broad"}
			globalKey := model.NetworkSetKey{Name: "global-narrow"}
			otherNsKey := model.NetworkSetKey{Name: "other-namespace/narrow"}

			it.InsertKey(broadCIDR, preferredNsKey)
			it.InsertKey(narrowCIDR, globalKey)
			it.InsertKey(narrowCIDR, otherNsKey)

			// Preferred namespace should still win despite having broader prefix
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "target-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(preferredNsKey)) // Namespace priority over prefix length

			// When preferred namespace doesn't exist, global should win (longer prefix)
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey)) // Global over other namespace

			// Test other namespace fallback by removing global
			it3 := NewIpTrie()
			it3.InsertKey(narrowCIDR, otherNsKey)

			key, found = it3.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(otherNsKey)) // Other namespace as last resort
		})
	})
})

// Tests for collector integration with namespace-aware lookups
var _ = Describe("Collector Integration Tests", func() {
	var lc *LookupsCache
	var nsCache *NetworkSetLookupsCache
	var testIP [16]byte

	BeforeEach(func() {
		lc = NewLookupsCache()
		nsCache = NewNetworkSetLookupsCache()

		ipAddr := mustParseIP("10.0.0.100").IP
		copy(testIP[:], ipAddr.To16())
	})

	Context("when testing collector namespace interface", func() {
		It("should expose namespace-aware lookups through LookupsCache", func() {
			// Verify that the collector interface has the namespace method
			Expect(lc).To(BeAssignableToTypeOf(&LookupsCache{}))

			// Test that the method exists and has the right signature
			_, found := lc.GetNetworkSetWithNamespace(testIP, "test-namespace")
			Expect(found).To(BeFalse()) // Should be false since no data loaded

			// Verify the method is available for collector usage
			Expect(lc.GetNetworkSetWithNamespace).ToNot(BeNil())
		})

		It("should delegate to optimized NetworkSetLookupsCache implementation", func() {
			// Create test data
			globalKey := model.NetworkSetKey{Name: "global-netset"}
			globalNS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.0.0.0/8"), // Broad CIDR
				},
			}

			ns1Key := model.NetworkSetKey{Name: "namespace1/specific-netset"}
			ns1NS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.0.0.0/24"), // More specific than global
				},
			}

			// Add to the underlying cache
			nsCache.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: globalKey, Value: &globalNS},
				UpdateType: api.UpdateTypeKVNew,
			})
			nsCache.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: ns1Key, Value: &ns1NS},
				UpdateType: api.UpdateTypeKVNew,
			})

			// Test direct NetworkSetLookupsCache usage (what collector uses)
			ed, found := nsCache.GetNetworkSetFromIPWithNamespace(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(ed.Key()).To(Equal(ns1Key))

			// Test fallback behavior
			ed, found = nsCache.GetNetworkSetFromIPWithNamespace(testIP, "nonexistent")
			Expect(found).To(BeTrue())
			Expect(ed.Key()).To(Equal(globalKey)) // Should return global as fallback

			// Verify legacy method still works
			ed2, found2 := nsCache.GetNetworkSetFromIP(testIP)
			Expect(found2).To(BeTrue())
			Expect(ed2.Key()).To(Equal(globalKey)) // Should return longest prefix match
		})

		It("should maintain performance with namespace-aware lookups", func() {
			// Add multiple NetworkSets across namespaces
			for i := 0; i < 10; i++ {
				key := model.NetworkSetKey{
					Name: fmt.Sprintf("namespace%d/test-netset", i),
				}
				ns := model.NetworkSet{
					Nets: []calinet.IPNet{
						calinet.MustParseNetwork(fmt.Sprintf("10.%d.0.0/16", i)),
					},
				}

				nsCache.OnUpdate(api.Update{
					KVPair:     model.KVPair{Key: key, Value: &ns},
					UpdateType: api.UpdateTypeKVNew,
				})
			}

			// Performance test: many lookups should complete quickly
			start := time.Now()
			for i := 0; i < 100; i++ {
				namespace := fmt.Sprintf("namespace%d", i%10)
				testIPLoop := [16]byte{}
				loopIP := mustParseIP(fmt.Sprintf("10.%d.1.1", i%10)).IP
				copy(testIPLoop[:], loopIP.To16())

				_, found := nsCache.GetNetworkSetFromIPWithNamespace(testIPLoop, namespace)
				Expect(found).To(BeTrue())
			}
			elapsed := time.Since(start)

			// Should complete 100 lookups in reasonable time
			Expect(elapsed).To(BeNumerically("<", 100*time.Millisecond))
		})
	})
})

// Tests for tie-breaking functionality - ensuring deterministic behavior when multiple
// network sets match the same IP with equal prefix lengths
var _ = Describe("IpTrie Tie-Breaking Functionality", func() {
	var it *IpTrie
	var testCIDR ip.CIDR
	var testIP ip.Addr

	BeforeEach(func() {
		it = NewIpTrie()
		testCIDR = ip.MustParseCIDROrIP("10.0.0.0/24")
		testIP = ip.FromNetIP(mustParseIP("10.0.0.100").IP)
	})

	Context("when multiple keys have the same prefix length", func() {
		It("should return the lexicographically smallest key name", func() {
			// Insert keys in reverse alphabetical order to test sorting
			zebraKey := model.NetworkSetKey{Name: "zebra-netset"}
			betaKey := model.NetworkSetKey{Name: "beta-netset"}
			alphaKey := model.NetworkSetKey{Name: "alpha-netset"}

			it.InsertKey(testCIDR, zebraKey)
			it.InsertKey(testCIDR, betaKey)
			it.InsertKey(testCIDR, alphaKey)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(alphaKey)) // Should return alpha (lexicographically smallest)
		})

		It("should be deterministic regardless of insertion order", func() {
			keys := []model.NetworkSetKey{
				{Name: "gamma-netset"},
				{Name: "alpha-netset"},
				{Name: "delta-netset"},
				{Name: "beta-netset"},
			}

			// Test multiple insertion orders
			for i := 0; i < 5; i++ {
				it := NewIpTrie()

				// Insert in different orders
				for j := i; j < len(keys)+i; j++ {
					it.InsertKey(testCIDR, keys[j%len(keys)])
				}

				key, found := it.GetLongestPrefixCidr(testIP)
				Expect(found).To(BeTrue())
				Expect(key).To(Equal(model.NetworkSetKey{Name: "alpha-netset"}))
			}
		})

		It("should handle single key correctly", func() {
			singleKey := model.NetworkSetKey{Name: "single-netset"}
			it.InsertKey(testCIDR, singleKey)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(singleKey))
		})

		It("should handle keys with special characters", func() {
			key1 := model.NetworkSetKey{Name: "z-special/netset"}
			key2 := model.NetworkSetKey{Name: "a-special_netset"}
			key3 := model.NetworkSetKey{Name: "m-special.netset"}

			it.InsertKey(testCIDR, key1)
			it.InsertKey(testCIDR, key2)
			it.InsertKey(testCIDR, key3)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(key2)) // "a-special_netset" is lexicographically smallest
		})
	})

	Context("when testing namespace-aware tie-breaking", func() {
		It("should break ties within the same namespace", func() {
			ns1Key1 := model.NetworkSetKey{Name: "namespace1/zebra-netset"}
			ns1Key2 := model.NetworkSetKey{Name: "namespace1/alpha-netset"}
			ns1Key3 := model.NetworkSetKey{Name: "namespace1/beta-netset"}

			it.InsertKey(testCIDR, ns1Key1)
			it.InsertKey(testCIDR, ns1Key2)
			it.InsertKey(testCIDR, ns1Key3)

			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns1Key2)) // namespace1/alpha-netset is lexicographically smallest
		})

		It("should prioritize global over other namespace keys when no preferred namespace match", func() {
			ns1Key := model.NetworkSetKey{Name: "namespace2/some-netset"}
			ns2Key := model.NetworkSetKey{Name: "namespace1/some-netset"}
			globalKey := model.NetworkSetKey{Name: "global-netset"}

			it.InsertKey(testCIDR, ns1Key)
			it.InsertKey(testCIDR, ns2Key)
			it.InsertKey(testCIDR, globalKey)

			// Request a namespace that doesn't exist, should prefer global over other namespaces
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey)) // Global key should be returned over other namespaces

			// Test fallback to other namespace when no global exists
			it2 := NewIpTrie()
			it2.InsertKey(testCIDR, ns1Key)
			it2.InsertKey(testCIDR, ns2Key)

			key, found = it2.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent")
			Expect(found).To(BeTrue())
			// Should return one of the namespace keys (lexicographically smallest)
			Expect(key).To(Equal(ns2Key)) // namespace1/some-netset is lexicographically smaller
		})

		It("should break ties between global keys", func() {
			globalKey1 := model.NetworkSetKey{Name: "zebra-global"}
			globalKey2 := model.NetworkSetKey{Name: "alpha-global"}

			it.InsertKey(testCIDR, globalKey1)
			it.InsertKey(testCIDR, globalKey2)

			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "any-namespace")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey2)) // alpha-global is lexicographically smallest
		})

		It("should prefer namespace match over global even if global is lexicographically smaller", func() {
			globalKey := model.NetworkSetKey{Name: "alpha-global"}
			nsKey := model.NetworkSetKey{Name: "namespace1/zebra-netset"}

			it.InsertKey(testCIDR, globalKey)
			it.InsertKey(testCIDR, nsKey)

			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(nsKey)) // Namespace match takes priority
		})

		It("should handle mixed global and namespace keys with proper tie-breaking", func() {
			// Same prefix length, different key types
			globalKey1 := model.NetworkSetKey{Name: "zebra-global"}
			globalKey2 := model.NetworkSetKey{Name: "alpha-global"}
			ns1Key1 := model.NetworkSetKey{Name: "namespace1/zebra-netset"}
			ns1Key2 := model.NetworkSetKey{Name: "namespace1/alpha-netset"}

			it.InsertKey(testCIDR, globalKey1)
			it.InsertKey(testCIDR, globalKey2)
			it.InsertKey(testCIDR, ns1Key1)
			it.InsertKey(testCIDR, ns1Key2)

			// When requesting namespace1, should get the lexicographically smallest within namespace1
			key, found := it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "namespace1")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(ns1Key2)) // namespace1/alpha-netset

			// When requesting non-existent namespace, should get lexicographically smallest global
			key, found = it.GetLongestPrefixCidrWithNamespaceIsolation(testIP, "nonexistent")
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(globalKey2)) // alpha-global
		})
	})

	Context("when testing with different prefix lengths", func() {
		It("should prioritize longer prefix over lexicographic order", func() {
			// Longer prefix should win even if name is lexicographically larger
			broadKey := model.NetworkSetKey{Name: "alpha-broad"}
			narrowKey := model.NetworkSetKey{Name: "zebra-narrow"}

			broadCIDR := ip.MustParseCIDROrIP("10.0.0.0/16")  // Less specific
			narrowCIDR := ip.MustParseCIDROrIP("10.0.0.0/24") // More specific

			it.InsertKey(broadCIDR, broadKey)
			it.InsertKey(narrowCIDR, narrowKey)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(narrowKey)) // Longer prefix wins despite larger name
		})

		It("should only apply tie-breaking when prefix lengths are equal", func() {
			// Different prefix lengths with multiple keys each
			broadKey1 := model.NetworkSetKey{Name: "zebra-broad"}
			broadKey2 := model.NetworkSetKey{Name: "alpha-broad"}
			narrowKey1 := model.NetworkSetKey{Name: "zebra-narrow"}
			narrowKey2 := model.NetworkSetKey{Name: "alpha-narrow"}

			broadCIDR := ip.MustParseCIDROrIP("10.0.0.0/16")
			narrowCIDR := ip.MustParseCIDROrIP("10.0.0.0/24")

			it.InsertKey(broadCIDR, broadKey1)
			it.InsertKey(broadCIDR, broadKey2)
			it.InsertKey(narrowCIDR, narrowKey1)
			it.InsertKey(narrowCIDR, narrowKey2)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			// Should get alpha-narrow (lexicographically smallest among the longest prefix matches)
			Expect(key).To(Equal(narrowKey2))
		})
	})

	Context("when testing edge cases", func() {
		It("should handle empty trie", func() {
			_, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeFalse())
		})

		It("should handle keys that differ only in casing", func() {
			key1 := model.NetworkSetKey{Name: "Alpha-netset"}
			key2 := model.NetworkSetKey{Name: "alpha-netset"}

			it.InsertKey(testCIDR, key1)
			it.InsertKey(testCIDR, key2)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			// "Alpha-netset" comes before "alpha-netset" in ASCII ordering
			Expect(key).To(Equal(key1))
		})

		It("should handle numeric suffixes correctly", func() {
			key1 := model.NetworkSetKey{Name: "netset-10"}
			key2 := model.NetworkSetKey{Name: "netset-2"}
			key3 := model.NetworkSetKey{Name: "netset-20"}

			it.InsertKey(testCIDR, key1)
			it.InsertKey(testCIDR, key2)
			it.InsertKey(testCIDR, key3)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			// String comparison: "netset-10" < "netset-2" < "netset-20"
			Expect(key).To(Equal(key1))
		})

		It("should handle very long key names", func() {
			shortKey := model.NetworkSetKey{Name: "z"}
			longKey := model.NetworkSetKey{Name: "a" + strings.Repeat("-very-long-name", 100)}

			it.InsertKey(testCIDR, shortKey)
			it.InsertKey(testCIDR, longKey)

			key, found := it.GetLongestPrefixCidr(testIP)
			Expect(found).To(BeTrue())
			Expect(key).To(Equal(longKey)) // Long key starting with "a" is lexicographically smaller
		})
	})
})
