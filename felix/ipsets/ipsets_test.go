// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
//
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

package ipsets_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ip"
	. "github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	ipSetID  = "s:qMt7iLlGDhvLnCjM0l9nzxbabcd"
	ipSetID2 = "t:qMt7iLlGDhvLnCjM0l9nzxbabcd"
	ipSetID3 = "u:qMt7iLlGDhvLnCjM0l9nzxbabcd"
	ipSetID4 = "v:qMt7iLlGDhvLnCjM0l9nzxbabcd"
	ipSetID5 = "w:qMt7iLlGDhvLnCjM0l9nzxbabcd"

	v4MainIPSetName  = "cali40s:qMt7iLlGDhvLnCjM0l9nzxb"
	v4TempIPSetName0 = "cali4t0"
	v4TempIPSetName1 = "cali4t1"
	v4TempIPSetName2 = "cali4t2"
	v4MainIPSetName2 = "cali40t:qMt7iLlGDhvLnCjM0l9nzxb"
	v4MainIPSetName3 = "cali40u:qMt7iLlGDhvLnCjM0l9nzxb"
)

var v4Members1And2 = []string{"10.0.0.1", "10.0.0.2"}

var exampleMembersByType = map[IPSetType][]string{
	IPSetTypeHashIP:     {"10.0.0.1", "10.0.0.2", "10.0.1.0"},
	IPSetTypeHashIPPort: {"10.0.0.1,tcp:8080", "10.0.0.1,tcp:8081", "10.0.0.2,udp:1234"},
	IPSetTypeHashNet:    {"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/25"},
	IPSetTypeBitmapPort: {"8080", "80", "443"},
	IPSetTypeHashNetNet: {"10.0.0.0/24,10.0.0.1/32", "10.0.1.0/24,10.0.0.2/32", "10.0.2.0/25,10.0.0.3/32"},
}

var _ = Describe("IPSetType", func() {
	It("should treat invalid strings as invalid", func() {
		Expect(IPSetType("").IsValid()).To(BeFalse())
	})
	It("should treat hash:ip as valid", func() {
		Expect(IPSetType("hash:ip").IsValid()).To(BeTrue())
	})
	It("should treat hash:net as valid", func() {
		Expect(IPSetType("hash:net").IsValid()).To(BeTrue())
	})
	It("should treat hash:ip,port as valid", func() {
		Expect(IPSetType("hash:ip,port").IsValid()).To(BeTrue())
	})
})

var _ = Describe("IPSetTypeHashIPPort", func() {
	It("should canonicalise an IPv4 IP,port", func() {
		Expect(CanonicaliseMember(IPSetTypeHashIPPort, "10.0.0.1,TCP:1234")).
			To(Equal(V4IPPort{
				IP:       ip.FromString("10.0.0.1").(ip.V4Addr),
				Protocol: labelindex.ProtocolTCP,
				Port:     1234,
			}))
	})
	It("should canonicalise an IPv4 SCTP IP,port", func() {
		Expect(CanonicaliseMember(IPSetTypeHashIPPort, "10.0.0.1,SCTP:1234")).
			To(Equal(V4IPPort{
				IP:       ip.FromString("10.0.0.1").(ip.V4Addr),
				Protocol: labelindex.ProtocolSCTP,
				Port:     1234,
			}))
	})
	It("should canonicalise an IPv6 IP,port", func() {
		Expect(CanonicaliseMember(IPSetTypeHashIPPort, "feed:0::beef,uDp:3456")).
			To(Equal(V6IPPort{
				IP:       ip.FromString("feed::beef").(ip.V6Addr),
				Protocol: labelindex.ProtocolUDP,
				Port:     3456,
			}))
	})
	It("should panic on bad IP,port", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashIPPort, "foobar") }).To(Panic())
	})
	It("should panic on bad IP,port (IP)", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashIPPort, "foobar,tcp:1234") }).To(Panic())
	})
	It("should panic on bad IP,port (protocol)", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashIPPort, "10.0.0.1,foo:1234") }).To(Panic())
	})
	It("should panic on bad IP,port (port)", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashIPPort, "10.0.0.1,tcp:bar") }).To(Panic())
	})
	It("should panic on bad IP,port (too long)", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashIPPort, "10.0.0.1,tcp:1234,5") }).To(Panic())
	})
	It("should detect IPv6 for an IP,port", func() {
		Expect(IPSetTypeHashIPPort.IsMemberIPV6("feed:beef::,tcp:1234")).To(BeTrue())
	})
	It("should detect IPv4 for an IP,port", func() {
		Expect(IPSetTypeHashIPPort.IsMemberIPV6("10.0.0.1,tcp:1234")).To(BeFalse())
	})
	It("should detect IPv6 for an IP,port", func() {
		Expect(IPSetTypeHashIPPort.IsMemberIPV6("feed:beef::,tcp:1234")).To(BeTrue())
	})
	It("should detect IPv4 for an IP,port", func() {
		Expect(IPSetTypeHashIPPort.IsMemberIPV6("10.0.0.0,tcp:1234")).To(BeFalse())
	})
})

var _ = Describe("IPSetTypeHashIP", func() {
	It("should canonicalise an IPv4", func() {
		Expect(CanonicaliseMember(IPSetTypeHashIP, "10.0.0.1")).
			To(Equal(ip.FromString("10.0.0.1")))
	})
	It("should canonicalise an IPv6", func() {
		Expect(CanonicaliseMember(IPSetTypeHashIP, "feed:0::beef")).
			To(Equal(ip.FromString("feed::beef")))
	})
	It("should panic on bad IP", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashIP, "foobar") }).To(Panic())
	})
})

var _ = Describe("IPSetTypeHashIP", func() {
	It("should canonicalise a raw port", func() {
		Expect(CanonicaliseMember(IPSetTypeBitmapPort, "10")).
			To(Equal(Port(10)))
	})
	It("should canonicalise an IPv4 port", func() {
		Expect(CanonicaliseMember(IPSetTypeBitmapPort, "v4,10")).
			To(Equal(Port(10)))
	})
	It("should canonicalise an IPv6 port", func() {
		Expect(CanonicaliseMember(IPSetTypeBitmapPort, "v6,10")).
			To(Equal(Port(10)))
	})
})

var _ = Describe("IPSetTypeHashNet", func() {
	It("should canonicalise an IPv4 CIDR", func() {
		Expect(CanonicaliseMember(IPSetTypeHashNet, "10.0.0.1/24")).
			To(Equal(ip.MustParseCIDROrIP("10.0.0.0/24")))
	})
	It("should canonicalise an IPv6 CIDR", func() {
		Expect(CanonicaliseMember(IPSetTypeHashNet, "feed::beef/24")).
			To(Equal(ip.MustParseCIDROrIP("feed::/24")))
	})
	It("should canonicalise an IPv4 IP as a CIDR", func() {
		Expect(CanonicaliseMember(IPSetTypeHashNet, "10.0.0.1")).
			To(Equal(ip.MustParseCIDROrIP("10.0.0.1/32")))
	})
	It("should canonicalise an IPv6 IP as a CIDR", func() {
		Expect(CanonicaliseMember(IPSetTypeHashNet, "feed::beef")).
			To(Equal(ip.MustParseCIDROrIP("feed::beef/128")))
	})
	It("should panic on bad CIDR", func() {
		Expect(func() { CanonicaliseMember(IPSetTypeHashNet, "foobar") }).To(Panic())
	})
})

var _ = Describe("IPPort types", func() {
	It("V4 should stringify correctly", func() {
		Expect(V4IPPort{
			IP:       ip.FromString("10.0.0.0").(ip.V4Addr),
			Protocol: labelindex.ProtocolTCP,
			Port:     1234,
		}.String()).To(Equal("10.0.0.0,tcp:1234"))
	})
	It("V6 should stringify correctly", func() {
		Expect(V6IPPort{
			IP:       ip.FromString("feed:beef::").(ip.V6Addr),
			Protocol: labelindex.ProtocolUDP,
			Port:     1234,
		}.String()).To(Equal("feed:beef::,udp:1234"))
	})
})

var _ = Describe("IPFamily", func() {
	It("should treat invalid strings as invalid", func() {
		Expect(IPFamily("").IsValid()).To(BeFalse())
	})
	It("should treat inet as valid", func() {
		Expect(IPFamily("inet").IsValid()).To(BeTrue())
	})
	It("should treat inet6 as valid", func() {
		Expect(IPFamily("inet6").IsValid()).To(BeTrue())
	})
})

var _ = Describe("IP sets dataplane", func() {
	var dataplane *mockDataplane
	var ipsets *IPSets

	meta := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID,
		Type:    IPSetTypeHashIP,
	}
	meta2 := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID2,
		Type:    IPSetTypeHashIP,
	}
	meta3 := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID3,
		Type:    IPSetTypeHashIP,
	}
	meta4 := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID4,
		Type:    IPSetTypeHashIP,
	}
	meta5 := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID5,
		Type:    IPSetTypeHashIP,
	}
	metaCIDRs := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID,
		Type:    IPSetTypeHashNet,
	}
	v4VersionConf := NewIPVersionConfig(
		IPFamilyV4,
		"cali",
		rules.AllHistoricIPSetNamePrefixes,
		rules.LegacyV4IPSetNames,
	)
	// v6VersionConf := NewIPVersionConfig(IPFamilyV6, "cali", nil, nil)

	reschedRequested := false
	apply := func() {
		ipsets.ApplyUpdates(nil)
		reschedRequested = ipsets.ApplyDeletions()
	}

	resyncAndApply := func() {
		ipsets.QueueResync()
		apply()
	}

	BeforeEach(func() {
		dataplane = newMockDataplane()
		ipsets = NewIPSetsWithShims(
			v4VersionConf,
			logutils.NewSummarizer("test loop"),
			dataplane.newCmd,
			dataplane.sleep,
		)
	})

	It("mainline: should pend updates until apply is called", func() {
		// Replace call adds an IP that will still be there after subsequent deletes and
		// one that will be deleted.
		ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		// Ditto, we add another two IPs, one of which will be removed before the Apply
		// calls.
		ipsets.AddMembers(ipSetID, []string{"10.0.0.3", "10.0.0.4"})
		// Then delete one from each previous add.
		ipsets.RemoveMembers(ipSetID, []string{"10.0.0.1", "10.0.0.4"})
		// Dataplane should still be empty.
		dataplane.ExpectMembers(map[string][]string{})
		// Apply updates.
		ipsets.ApplyDeletions() // No-op
		dataplane.ExpectMembers(map[string][]string{})
		ipsets.ApplyUpdates(nil)
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.2", "10.0.0.3"},
		})

		// Check that batching is working as expected.
		Expect(dataplane.NumRestoreCalls()).To(Equal(1))
	})

	It("mainline: should ignore IPs of wrong version", func() {
		ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2", "fe80::1", "fe80::2"})
		ipsets.AddMembers(ipSetID, []string{"10.0.0.3", "10.0.0.4", "fe80::2", "fe80::3"})
		ipsets.RemoveMembers(ipSetID, []string{"10.0.0.1", "10.0.0.4", "fe80::2", "fe80::3"})
		apply()
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.2", "10.0.0.3"},
		})
	})

	It("should not mark set as dirty if all IPs of wrong version", func() {
		// Create the IP set.
		ipsets.AddOrReplaceIPSet(meta, []string{})
		apply()

		// Then, clear out the recorded commands so we can check that no more are issued.
		dataplane.CmdNames = nil

		// Do the no-op updates.
		ipsets.AddMembers(ipSetID, []string{"fe80::2", "fe80::3"})
		apply()
		Expect(dataplane.CmdNames).To(BeNil())
		ipsets.RemoveMembers(ipSetID, []string{"fe80::2", "fe80::3"})
		apply()

		Expect(dataplane.CmdNames).To(BeNil(), "updates should have been no-ops")
	})

	Describe("with left-over IP sets in place", func() {
		BeforeEach(func() {
			dataplane.IPSetMembers = map[string]set.Set[string]{
				v4MainIPSetName:  set.From("10.0.0.1"),
				v4TempIPSetName1: set.From("10.0.0.2"),
				v4MainIPSetName2: set.From("10.0.0.3"),
			}
		})

		It("should rate limit clean up", func() {
			apply()
			// MaxIPSetDeletionsPerIteration defaults to 1, so it should
			// delete one temp and one normal IP set.
			Expect(dataplane.IPSetMembers).To(HaveLen(1))
			Expect(reschedRequested).To(BeTrue(),
				"should reschedule if there are some IP sets still to delete")
			apply()
			// Should delete one temp and one normal IP set.
			Expect(dataplane.IPSetMembers).To(BeEmpty())
			Expect(reschedRequested).To(BeFalse(),
				"should not reschedule if there are no IP sets to delete")
		})

		It("should rewrite IP set correctly and clean up temp set", func() {
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			apply()
			Expect(dataplane.IPSetMembers).To(Equal(map[string]set.Set[string]{
				v4MainIPSetName: set.From("10.0.0.1", "10.0.0.2"),
			}))
			// It shouldn't try to double-delete the temp IP set.
			Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
		})
	})

	for _, ipSetType := range AllIPSetTypes {
		dataplaneMeta := setMetadata{
			Name:   v4MainIPSetName,
			Family: "inet",
			Type:   ipSetType,
		}
		if ipSetType == IPSetTypeBitmapPort {
			dataplaneMeta.RangeMin = 10
			dataplaneMeta.RangeMax = 1024
		} else {
			dataplaneMeta.MaxSize = 1024
		}

		ipSetType := ipSetType
		Describe("Resync re-use tests for "+string(ipSetType), func() {
			members := exampleMembersByType[ipSetType]

			BeforeEach(func() {
				Expect(len(members)).To(BeNumerically(">=", 3),
					"Need at least 3 example members of type "+ipSetType)
				dataplane.IPSetMembers = map[string]set.Set[string]{
					v4MainIPSetName: set.FromArray(members[0:2]),
				}
				dataplane.IPSetMetadata = map[string]setMetadata{
					v4MainIPSetName: dataplaneMeta,
				}
			})

			It("should be a valid IP set type", func() {
				Expect(ipSetType.IsValid()).To(BeTrue(), "IP set type didn't this it was valid")
			})

			It("IP set should get reused if metadata is compatible", func() {
				ipsets.AddOrReplaceIPSet(IPSetMetadata{
					// Copy the dataplane metadata.  Only MaxSize or the Range values will be non-0.
					MaxSize:  dataplaneMeta.MaxSize,
					RangeMin: dataplaneMeta.RangeMin,
					RangeMax: dataplaneMeta.RangeMax,

					SetID: ipSetID,
					Type:  ipSetType,
				}, []string{members[0], members[2]})
				apply()
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: {members[0], members[2]},
				})
				Expect(dataplane.LinesExecuted).To(Equal([]string{
					"del " + v4MainIPSetName + " " + members[1] + " --exist",
					"add " + v4MainIPSetName + " " + members[2],
					"COMMIT",
				}), "Expected a minimal update to add/del one entry")
			})

			It("should get rewritten if metadata is not compatible", func() {
				metadata := IPSetMetadata{
					SetID: ipSetID,
					Type:  ipSetType,
				}
				var headerStr string
				if dataplaneMeta.MaxSize > 0 {
					// Hash-based IP set.
					metadata.MaxSize = dataplaneMeta.MaxSize + 1
					headerStr = fmt.Sprintf("family inet maxelem %d", metadata.MaxSize)
				} else {
					// Bitmap-based IP set ahs a range, not a maxelems.
					metadata.RangeMin = dataplaneMeta.RangeMin + 1
					metadata.RangeMax = dataplaneMeta.RangeMax + 1
					headerStr = fmt.Sprintf("range %d-%d", metadata.RangeMin, metadata.RangeMax)
				}
				ipsets.AddOrReplaceIPSet(metadata, []string{members[0]})
				apply()
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: {members[0]},
				})
				Expect(dataplane.LinesExecuted).To(Equal([]string{
					"create cali4t0 " + string(ipSetType) + " " + headerStr,
					"add cali4t0 " + members[0],
					"swap " + v4MainIPSetName + " cali4t0",
					"COMMIT",
				}), "Expected a full rewrite")
			})
		})
	}

	Describe("with an unsupported calico IP set type in the dataplane", func() {
		BeforeEach(func() {
			dataplane.IPSetMembers = map[string]set.Set[string]{
				v4MainIPSetName: set.From("unsupported-member"),
			}
			dataplane.IPSetMetadata = map[string]setMetadata{
				v4MainIPSetName: {
					Name:    v4MainIPSetName,
					Family:  "inet",
					Type:    "unknown:type",
					MaxSize: 1234,
				},
			}
		})

		It("IP set should get cleaned up", func() {
			apply()
			dataplane.ExpectMembers(map[string][]string{})
		})
	})

	Describe("with many left-over IP sets in place", func() {
		BeforeEach(func() {
			for i := 0; i < MaxIPSetDeletionsPerIteration*3; i++ {
				setName := fmt.Sprintf("cali40s:%d", i)
				dataplane.IPSetMembers[setName] = set.From("10.0.0.1")
			}
		})

		It("should have limit on number of deletions per attempt", func() {
			apply()
			Expect(dataplane.IPSetMembers).To(HaveLen(MaxIPSetDeletionsPerIteration * 2))
			apply()
			Expect(dataplane.IPSetMembers).To(HaveLen(MaxIPSetDeletionsPerIteration))
			apply()
			Expect(dataplane.IPSetMembers).To(HaveLen(0))
			Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
		})

		It("should rewrite IP set correctly and clean up temp set", func() {
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			apply()
			Expect(dataplane.IPSetMembers[v4MainIPSetName]).To(Equal(set.From("10.0.0.1", "10.0.0.2")))
			// It shouldn't try to double-delete the temp IP set.
			Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
		})
	})

	Describe("with a persistent failure to delete a new temporary IP set", func() {
		BeforeEach(func() {
			// writeFullRewrite will only use a temp IP set if the main IP set exists
			// and it has the wrong maxelems.
			dataplane.IPSetMembers[v4MainIPSetName] = set.New[string]()
			dataplane.IPSetMetadata[v4MainIPSetName] = setMetadata{
				Name:    "v4MainIPSetName",
				Family:  "inet",
				Type:    "hash:ip",
				MaxSize: 5678,
			}

			// Lay the trap: this should be the first temp IP set to get used.
			dataplane.FailDestroyNames.Add(v4TempIPSetName0)
		})

		AfterEach(func() {
			// It shouldn't try to double-add/delete anything.
			Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
			Expect(dataplane.TriedToAddExistent).To(BeFalse())
		})

		It("should rewrite IP set correctly on first apply()", func() {
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			apply()

			By("Creating the main IP set and leaving the temp IP set left over.")
			Expect(dataplane.IPSetMembers).To(Equal(map[string]set.Set[string]{
				v4TempIPSetName0: set.From[string](),
				v4MainIPSetName:  set.From("10.0.0.1", "10.0.0.2"),
			}))

			By("Using the correct sequence of destroys")
			Expect(dataplane.AttemptedDestroys).To(Equal([]string{
				v4TempIPSetName0, // Attempted deletion in ApplyDeletions().
			}))

			By("Leaving the resync flag unset")
			dataplane.AttemptedDestroys = nil
			apply()
			Expect(dataplane.AttemptedDestroys).To(BeEmpty())
		})
	})

	Describe("with a persistent failure to delete a preexisting temporary IP set", func() {
		BeforeEach(func() {
			dataplane.IPSetMembers = map[string]set.Set[string]{
				v4MainIPSetName:  set.From("10.0.0.1"),
				v4TempIPSetName1: set.From("10.0.0.2"),
				v4TempIPSetName2: set.From("10.0.0.2"),
				v4MainIPSetName2: set.From("10.0.0.3"),
			}
			dataplane.FailDestroyNames.Add(v4TempIPSetName1)
		})

		AfterEach(func() {
			// It shouldn't try to double-add/delete anything.
			Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
			Expect(dataplane.TriedToAddExistent).To(BeFalse())
		})

		Describe("after first apply()", func() {
			BeforeEach(apply)

			It("should clean up one IP set of each kind on first apply()", func() {
				Expect(dataplane.IPSetMembers).To(HaveLen(2))
				Expect(dataplane.IPSetMembers).To(HaveKey(v4TempIPSetName1))
			})

			It("second apply shouldn't retry deletions", func() {
				dataplane.AttemptedDestroys = nil
				apply()

				Expect(dataplane.IPSetMembers).To(Equal(map[string]set.Set[string]{
					v4TempIPSetName1: set.From("10.0.0.2"),
				}))

				dataplane.AttemptedDestroys = nil
				ipsets.QueueResync()
				apply()

				Expect(dataplane.AttemptedDestroys).To(ConsistOf(
					v4TempIPSetName1,
					v4TempIPSetName1,
				))

				By("should succeed once error is cleared")
				dataplane.FailDestroyNames.Clear()
				dataplane.AttemptedDestroys = nil
				ipsets.QueueResync()
				apply()

				Expect(dataplane.IPSetMembers).To(Equal(map[string]set.Set[string]{}))
				Expect(dataplane.AttemptedDestroys).To(Equal([]string{v4TempIPSetName1}))

				By("And should be idempotent")
				dataplane.AttemptedDestroys = nil
				apply()
				Expect(dataplane.AttemptedDestroys).To(BeEmpty())
			})
		})

		It("should rewrite IP set correctly on first apply()", func() {
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			apply()
			Expect(dataplane.IPSetMembers).To(Equal(map[string]set.Set[string]{
				v4TempIPSetName1: set.From("10.0.0.2"),
				v4MainIPSetName:  set.From("10.0.0.1", "10.0.0.2"),
			}))
		})
	})

	Context("with filtering to two IP sets", func() {
		BeforeEach(func() {
			ipsets.SetFilter(set.From(v4MainIPSetName2, v4MainIPSetName))
			ipsets.QueueResync()
			apply()
		})

		It("should create only those two", func() {
			// Regression test for a bug hit during development; we were breaking out of
			// the loop when we hit an ignored IP set.  Make sure we have a few IP sets
			// so it's very unlikely to pass by chance.
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			ipsets.AddOrReplaceIPSet(meta2, []string{"10.0.0.2", "10.0.0.3"})
			ipsets.AddOrReplaceIPSet(meta3, []string{"10.0.0.3", "10.0.0.4"})
			ipsets.AddOrReplaceIPSet(meta4, []string{"10.0.0.4", "10.0.0.5"})
			ipsets.AddOrReplaceIPSet(meta5, []string{"10.0.0.5", "10.0.0.6"})
			apply()

			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
				v4MainIPSetName2: {"10.0.0.2", "10.0.0.3"},
			})
		})
	})

	Describe("after creating an IP set", func() {
		BeforeEach(func() {
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			apply()
		})

		It("add in its own batch should add the IP", func() {
			ipsets.AddMembers(ipSetID, []string{"10.0.0.3", "10.0.0.4"})
			apply()
			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName: {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
			})
		})

		It("remove IP in its own batch should remove the IP", func() {
			ipsets.RemoveMembers(ipSetID, []string{"10.0.0.2"})
			apply()
			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName: {"10.0.0.1"},
			})
		})

		It("remove set in its own batch should delete the set", func() {
			ipsets.RemoveIPSet(ipSetID)
			apply()
			dataplane.ExpectMembers(map[string][]string{})
		})

		It("an add, then remove should be squashed", func() {
			ipsets.AddMembers(ipSetID, []string{"10.0.0.3"})
			ipsets.RemoveMembers(ipSetID, []string{"10.0.0.3"})
			apply()
			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName: {"10.0.0.1", "10.0.0.2"},
			})
		})
		It("a remove, then re-add should be squashed", func() {
			ipsets.RemoveMembers(ipSetID, []string{"10.0.0.2"})
			ipsets.AddMembers(ipSetID, []string{"10.0.0.2"})
			apply()
			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName: {"10.0.0.1", "10.0.0.2"},
			})
		})
		It("an add, then remove then an add should be handled", func() {
			ipsets.AddMembers(ipSetID, []string{"10.0.0.3"})
			ipsets.RemoveMembers(ipSetID, []string{"10.0.0.3"})
			ipsets.AddMembers(ipSetID, []string{"10.0.0.3"})
			apply()
			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName: {"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			})
		})
		It("a remove, then re-add should be handled", func() {
			ipsets.RemoveMembers(ipSetID, []string{"10.0.0.2"})
			ipsets.AddMembers(ipSetID, []string{"10.0.0.2"})
			ipsets.RemoveMembers(ipSetID, []string{"10.0.0.2"})
			apply()
			dataplane.ExpectMembers(map[string][]string{
				v4MainIPSetName: {"10.0.0.1"},
			})
		})

		Describe("after creating second IP set", func() {
			BeforeEach(func() {
				ipsets.AddOrReplaceIPSet(meta2, []string{"10.0.0.1", "10.0.0.3"})
				apply()
			})

			It("should update the dataplane", func() {
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
					v4MainIPSetName2: {"10.0.0.1", "10.0.0.3"},
				})
			})

			Context("with filtering to single IP set", func() {
				BeforeEach(func() {
					ipsets.SetFilter(set.From(v4MainIPSetName2))
					apply()
				})

				It("should delete the non-needed IP set", func() {
					Expect(dataplane.AttemptedDestroys).To(Equal([]string{
						v4MainIPSetName,
					}))
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName2: {"10.0.0.1", "10.0.0.3"},
					})
				})

				Context("with filtering to both known IP sets", func() {
					BeforeEach(func() {
						ipsets.SetFilter(set.From(v4MainIPSetName2, v4MainIPSetName))
						apply()
					})

					It("should recreate the re-needed IP set", func() {
						dataplane.ExpectMembers(map[string][]string{
							v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
							v4MainIPSetName2: {"10.0.0.1", "10.0.0.3"},
						})
					})
				})
			})

			Describe("after another process modifies an IP set", func() {
				BeforeEach(func() {
					dataplane.IPSetMembers[v4MainIPSetName] = set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
				})

				It("should be detected and fixed by a resync", func() {
					resyncAndApply()
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
						v4MainIPSetName2: {"10.0.0.1", "10.0.0.3"},
					})
				})
			})

			Describe("after another process flushes an IP set", func() {
				BeforeEach(func() {
					dataplane.IPSetMembers[v4MainIPSetName] = set.New[string]()
				})

				It("should be detected and fixed by a resync", func() {
					resyncAndApply()
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
						v4MainIPSetName2: {"10.0.0.1", "10.0.0.3"},
					})
				})
			})
		})

		Describe("after another process modifies the IP set", func() {
			BeforeEach(func() {
				dataplane.IPSetMembers[v4MainIPSetName] = set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
			})

			It("should be detected and fixed by a resync", func() {
				resyncAndApply()
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: v4Members1And2,
				})
			})
			It("should be detected and fixed after an inconsistent add", func() {
				ipsets.AddMembers(ipSetID, []string{"10.0.0.3"})
				apply()
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: {"10.0.0.1", "10.0.0.2", "10.0.0.3"},
				})
			})
			It("should not be detected and fixed after an inconsistent remove", func() {
				// We use '--exist' on 'del' commands to reduce the impact of
				// https://github.com/projectcalico/felix/issues/1347.  If we resync
				// after every remove failure when updating a large IP set we can
				// end up in a resync loop requiring many retries to bring the
				// set into sync.  That means that we won't spot the inconsistency
				// in that case.
				ipsets.RemoveMembers(ipSetID, []string{"10.0.0.2"})
				apply()
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: {"10.0.0.1", "10.0.0.3", "10.0.0.4"},
				})
			})
			It("should not be detected if update succeeds", func() {
				ipsets.AddMembers(ipSetID, []string{"10.0.0.5"})
				apply()
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: {"10.0.0.1", "10.0.0.3", "10.0.0.4", "10.0.0.5"},
				})
			})
		})

		Describe("with a persistent ipset restore failure", func() {
			BeforeEach(func() {
				dataplane.FailAllRestores = true
			})
			It("should panic eventually", func() {
				ipsets.AddMembers(ipSetID, []string{"10.0.0.5"})
				Expect(func() { ipsets.ApplyUpdates(nil) }).To(Panic())
				Expect(dataplane.CumulativeSleep).To(BeNumerically(">", time.Second))
			})
		})
		Describe("with a persistent ipset list failure", func() {
			BeforeEach(func() {
				dataplane.FailAllLists = true
			})
			It("should panic eventually", func() {
				ipsets.QueueResync()
				Expect(func() { ipsets.ApplyUpdates(nil) }).To(Panic())
				Expect(dataplane.CumulativeSleep).To(BeNumerically(">", time.Second))
			})
		})
		Describe("with a persistent ipset list/restore failure", func() {
			BeforeEach(func() {
				dataplane.FailAllLists = true
				dataplane.FailAllRestores = true
			})
			It("should panic eventually", func() {
				ipsets.QueueResync()
				Expect(func() { ipsets.ApplyUpdates(nil) }).To(Panic())
				Expect(dataplane.CumulativeSleep).To(BeNumerically(">", time.Second))
			})
		})
		Describe("with various transient list failures queued up", func() {
			BeforeEach(func() {
				dataplane.IPSetMembers[v4MainIPSetName] = set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
				dataplane.ListOpFailures = []string{"pipe", "start", "read", "read-member", "member", "rc"}
			})

			It("it should get there in the end", func() {
				resyncAndApply()
				Expect(dataplane.CumulativeSleep).To(BeNumerically(">", 0))
				dataplane.ExpectMembers(map[string][]string{
					v4MainIPSetName: v4Members1And2,
				})
			})
		})

		describeResyncFailureTests := func(failures ...string) func() {
			return func() {
				BeforeEach(func() {
					dataplane.IPSetMembers[v4MainIPSetName] = set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
					dataplane.ListOpFailures = failures
				})
				AfterEach(func() {
					// All the errors should be consumed.
					Expect(dataplane.ListOpFailures).To(BeEmpty())
				})

				It("resync should be retried", func() {
					resyncAndApply()
					Expect(dataplane.CumulativeSleep).To(BeNumerically(">", 0))
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName: v4Members1And2,
					})
				})
			}
		}

		Describe("with a failure to create ipset list pipe", describeResyncFailureTests("pipe"))
		Describe("with a failure to start ipset list", describeResyncFailureTests("start"))
		Describe("with a failure to read straight away", describeResyncFailureTests("read"))
		Describe("with a failure to read a member", describeResyncFailureTests("read-member"))
		Describe("with a failure to close pipe", describeResyncFailureTests("close"))
		Describe("with a failure to close pipe and a good RC", describeResyncFailureTests("close", "force-good-rc"))
		Describe("with a failure return code", describeResyncFailureTests("rc"))

		describeRetryTests := func(failures ...string) func() {
			return func() {
				BeforeEach(func() {
					dataplane.RestoreOpFailures = failures
				})
				AfterEach(func() {
					// All the errors should be consumed.
					Expect(dataplane.RestoreOpFailures).To(BeEmpty())
				})

				It("a create should be retried until it succeeds", func() {
					ipsets.AddOrReplaceIPSet(meta2, []string{"10.0.0.3", "10.0.0.4"})
					ipsets.AddOrReplaceIPSet(meta3, []string{"10.0.0.5", "10.0.0.6"})
					apply()
					Expect(dataplane.CumulativeSleep).To(BeNumerically(">", 0))
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
						v4MainIPSetName2: {"10.0.0.3", "10.0.0.4"},
						v4MainIPSetName3: {"10.0.0.5", "10.0.0.6"},
					})
					Expect(dataplane.TriedToAddExistent).To(BeFalse())
					Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
				})

				It("an add should be retried until it succeeds", func() {
					ipsets.AddMembers(ipSetID, []string{"10.0.0.3"})
					apply()
					Expect(dataplane.CumulativeSleep).To(BeNumerically(">", 0))
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName: {"10.0.0.1", "10.0.0.2", "10.0.0.3"},
					})
					Expect(dataplane.TriedToAddExistent).To(BeFalse())
					Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
				})

				It("a remove should be retried until it succeeds", func() {
					ipsets.RemoveMembers(ipSetID, []string{"10.0.0.2"})
					apply()
					Expect(dataplane.CumulativeSleep).To(BeNumerically(">", 0))
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName: {"10.0.0.1"},
					})
					Expect(dataplane.TriedToAddExistent).To(BeFalse())
					Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
				})
			}
		}

		Describe("with a failure to create the ipset restore pipe", describeRetryTests("pipe"))
		Describe("with a failure to start ipset restore", describeRetryTests("start"))
		Describe("with a failure to start ipset restore and a close failure", describeRetryTests(
			"close" /* needs to be queued up before the start */, "start"))
		Describe("with a write failure to the pipe (immediately)", describeRetryTests("write"))
		Describe("with a write failure to the pipe when writing an IP (single write only)", describeRetryTests("write-ip-only"))
		Describe("with a write failure to the pipe when writing an IP", describeRetryTests("write-ip"))
		Describe("with an update failure before any updates succeed", describeRetryTests("pre-update"))
		Describe("with an update failure after updates succeed", describeRetryTests("post-update"))
		Describe("with a couple of failures", describeRetryTests("pre-update", "post-update"))
	})

	Describe("with an IP set using non-canon CIDRs", func() {
		BeforeEach(func() {
			ipsets.AddOrReplaceIPSet(metaCIDRs, []string{"10.1.2.3/16", "10.0.0.0/16"})
			apply()
		})
		It("should write canonical form", func() {
			Expect(dataplane.IPSetMembers[v4MainIPSetName]).
				To(Equal(set.From("10.1.0.0/16", "10.0.0.0/16")))
		})
		It("shouldn't do any work on resync", func() {
			dataplane.CmdNames = nil
			resyncAndApply()
			Expect(dataplane.CmdNames).To(ConsistOf("list", "list"))
		})
	})

	It("remove set before apply should be no-op", func() {
		// This checks that the dirty flag is set by the remove method.
		ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		ipsets.RemoveIPSet(ipSetID)
		apply()

		dataplane.ExpectMembers(map[string][]string{})
		// Check there were no restore commands.
		Expect(dataplane.CmdNames).To(ConsistOf("list"))
	})
	It("remove set should be retried on next resync", func() {
		ipsets.AddOrReplaceIPSet(meta, v4Members1And2)
		apply()

		dataplane.FailNextDestroy = true
		ipsets.RemoveIPSet(ipSetID)
		apply()
		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})

		resyncAndApply()
		dataplane.ExpectMembers(map[string][]string{})
	})
	It("cleanup should remove unknown IP sets", func() {
		staleSet := set.New[string]()
		staleSet.Add("10.0.0.1")
		staleSet.Add("10.0.0.2")
		dataplane.IPSetMembers["cali40unknown"] = staleSet
		dataplane.IPSetMembers["cali4tunknown"] = staleSet
		ipsets.AddOrReplaceIPSet(meta, v4Members1And2)

		resyncAndApply()

		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
	})
	It("cleanup should ignore active IP sets", func() {
		ipsets.AddOrReplaceIPSet(meta, v4Members1And2)
		apply()
		resyncAndApply()
		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
	})
	It("cleanup should remove unexpected temporary IP sets", func() {
		// Add an IP set.
		ipsets.AddOrReplaceIPSet(meta, v4Members1And2)
		apply()

		// Recreate its temporary set, then resync.
		dataplane.IPSetMembers[v4TempIPSetName1] = set.From("10.0.0.1")
		resyncAndApply()

		// Should be cleaned up.
		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
	})
	It("cleanup should ignore non-calico IP sets", func() {
		nonCaliSet := set.New[string]()
		nonCaliSet.Add("10.0.0.1")
		nonCaliSet.Add("10.0.0.2")
		dataplane.IPSetMembers["noncali"] = nonCaliSet

		apply()
		resyncAndApply()
		dataplane.ExpectMembers(map[string][]string{"noncali": v4Members1And2})
	})
	It("CalicoIPSets() should ignore non-calico IP sets", func() {
		dataplane.IPSetMembers["noncali"] = set.From("10.0.0.1", "10.0.0.2")
		dataplane.IPSetMembers[v4MainIPSetName] = set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")

		ipsets, err := ipsets.CalicoIPSets()
		Expect(err).NotTo(HaveOccurred())
		Expect(ipsets).Should(Equal([]string{v4MainIPSetName}))
	})
})

var _ = Describe("Standard IPv4 IPVersionConfig", func() {
	v4VersionConf := NewIPVersionConfig(
		IPFamilyV4,
		"cali",
		rules.AllHistoricIPSetNamePrefixes,
		rules.LegacyV4IPSetNames,
	)
	It("should own its own chains", func() {
		Expect(v4VersionConf.OwnsIPSet("cali40s:abcdef12345_-")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("cali4ts:abcdef12345_-")).To(BeTrue())
	})
	It("should own legacy special case chains", func() {
		Expect(v4VersionConf.OwnsIPSet("felix-masq-ipam-pools")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("felix-all-ipam-pools")).To(BeTrue())
	})
	It("should own legacy chains", func() {
		Expect(v4VersionConf.OwnsIPSet("felix-4-foobar")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("felix-4t-foobar")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("cali4-s:abcdef12345_-")).To(BeTrue())
	})
	It("should not own chains from another version", func() {
		Expect(v4VersionConf.OwnsIPSet("cali60s:abcdef12345_-")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("cali6ts:abcdef12345_-")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("felix-6-foobar")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("felix-6t-foobar")).To(BeFalse())
	})
	It("should not own other chains", func() {
		Expect(v4VersionConf.OwnsIPSet("foobar")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("noncali")).To(BeFalse())
	})
	It("should work with StripPrefix", func() {
		Expect(StripIPSetNamePrefix(v4VersionConf.NameForMainIPSet(ipSetID))).To(HavePrefix(ipSetID[:20]))
	})
})

var _ = DescribeTable("ParseRange tests",
	func(input string, expMin, expMax int, errorExpected bool) {
		rMin, rMax, err := ParseRange(input)
		if errorExpected {
			Expect(err).To(HaveOccurred())
			return
		} else {
			Expect(err).NotTo(HaveOccurred())
		}

		Expect(rMin).To(Equal(expMin))
		Expect(rMax).To(Equal(expMax))
	},
	Entry("0-20", "0-20", 0, 20, false),
	Entry("1-20", "1-20", 1, 20, false),
	Entry("1-FOO", "1-FOO", 0, 0, true),
	Entry("FOO-1", "FOO-1", 0, 0, true),
	Entry("FOO", "FOO", 0, 0, true),
)
