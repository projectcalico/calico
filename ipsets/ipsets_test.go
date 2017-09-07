// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"time"

	"github.com/projectcalico/felix/ip"
	. "github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/labelindex"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	ipSetID  = "s:qMt7iLlGDhvLnCjM0l9nzxbabcd"
	ipSetID2 = "t:qMt7iLlGDhvLnCjM0l9nzxbabcd"

	v4MainIPSetName  = "cali4-s:qMt7iLlGDhvLnCjM0l9nzxb"
	v4TempIPSetName  = "cali4ts:qMt7iLlGDhvLnCjM0l9nzxb"
	v4MainIPSetName2 = "cali4-t:qMt7iLlGDhvLnCjM0l9nzxb"
	v4TempIPSetName2 = "cali4tt:qMt7iLlGDhvLnCjM0l9nzxb"

	v6MainIPSetName = "cali6-s:qMt7iLlGDhvLnCjM0l9nzxb"
	v6TempIPSetName = "cali6ts:qMt7iLlGDhvLnCjM0l9nzxb"
)

var (
	v4Members1And2  = []string{"10.0.0.1", "10.0.0.2"}
	v4Members12And3 = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	v4Members2And3  = []string{"10.0.0.2", "10.0.0.3"}

	v6Members1And2 = []string{"fe80::1", "fe80::2"}
)

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
	It("should return its string form from SetType()", func() {
		Expect(IPSetTypeHashIPPort.SetType()).To(Equal("hash:ip,port"))
	})
	It("should canonicalise an IPv4", func() {
		Expect(IPSetTypeHashIP.CanonicaliseMember("10.0.0.1")).
			To(Equal(ip.FromString("10.0.0.1")))
	})
	It("should canonicalise an IPv6", func() {
		Expect(IPSetTypeHashIP.CanonicaliseMember("feed:0::beef")).
			To(Equal(ip.FromString("feed::beef")))
	})
	It("should canonicalise an IPv4 IP,port", func() {
		Expect(IPSetTypeHashIPPort.CanonicaliseMember("10.0.0.1,TCP:1234")).
			To(Equal(V4IPPort{
				IP:       ip.FromString("10.0.0.1").(ip.V4Addr),
				Protocol: labelindex.ProtocolTCP,
				Port:     1234,
			}))
	})
	It("should canonicalise an IPv6 IP,port", func() {
		Expect(IPSetTypeHashIPPort.CanonicaliseMember("feed:0::beef,uDp:3456")).
			To(Equal(V6IPPort{
				IP:       ip.FromString("feed::beef").(ip.V6Addr),
				Protocol: labelindex.ProtocolUDP,
				Port:     3456,
			}))
	})
	It("should canonicalise an IPv4 CIDR", func() {
		Expect(IPSetTypeHashNet.CanonicaliseMember("10.0.0.1/24")).
			To(Equal(ip.MustParseCIDR("10.0.0.0/24")))
	})
	It("should canonicalise an IPv6 CIDR", func() {
		Expect(IPSetTypeHashNet.CanonicaliseMember("feed::beef/24")).
			To(Equal(ip.MustParseCIDR("feed::/24")))
	})
	It("should panic on bad IP", func() {
		Expect(func() { IPSetTypeHashIP.CanonicaliseMember("foobar") }).To(Panic())
	})
	It("should panic on bad IP,port", func() {
		Expect(func() { IPSetTypeHashIPPort.CanonicaliseMember("foobar") }).To(Panic())
	})
	It("should panic on bad IP,port (IP)", func() {
		Expect(func() { IPSetTypeHashIPPort.CanonicaliseMember("foobar,tcp:1234") }).To(Panic())
	})
	It("should panic on bad IP,port (protocol)", func() {
		Expect(func() { IPSetTypeHashIPPort.CanonicaliseMember("10.0.0.1,foo:1234") }).To(Panic())
	})
	It("should panic on bad IP,port (port)", func() {
		Expect(func() { IPSetTypeHashIPPort.CanonicaliseMember("10.0.0.1,tcp:bar") }).To(Panic())
	})
	It("should panic on bad IP,port (too long)", func() {
		Expect(func() { IPSetTypeHashIPPort.CanonicaliseMember("10.0.0.1,tcp:1234,5") }).To(Panic())
	})
	It("should panic on bad CIDR", func() {
		Expect(func() { IPSetTypeHashNet.CanonicaliseMember("foobar") }).To(Panic())
	})
	It("should detect IPv6 for an IP,port", func() {
		Expect(IPSetTypeHashIPPort.IsMemberIPV6("feed:beef::,tcp:1234")).To(BeTrue())
	})
	It("should detect IPv4 for an IP,port", func() {
		Expect(IPSetTypeHashIPPort.IsMemberIPV6("10.0.0.1,tcp:1234")).To(BeFalse())
	})
})

var _ = Describe("IPPort types", func() {
	It("V4 should stringify correctly", func() {
		Expect(V4IPPort{
			IP:       ip.FromString("10.0.0.1").(ip.V4Addr),
			Protocol: labelindex.ProtocolTCP,
			Port:     1234,
		}.String()).To(Equal("10.0.0.1,tcp:1234"))
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
	//v6VersionConf := NewIPVersionConfig(IPFamilyV6, "cali", nil, nil)

	apply := func() {
		ipsets.ApplyUpdates()
		ipsets.ApplyDeletions()
	}

	resyncAndApply := func() {
		ipsets.QueueResync()
		apply()
	}

	BeforeEach(func() {
		dataplane = newMockDataplane()
		ipsets = NewIPSetsWithShims(
			v4VersionConf,
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
		ipsets.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.2", "10.0.0.3"},
		})
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
			dataplane.IPSetMembers = map[string]set.Set{
				v4MainIPSetName:  set.From("10.0.0.1"),
				v4TempIPSetName:  set.From("10.0.0.2"),
				v4MainIPSetName2: set.From("10.0.0.3"),
			}
		})

		It("should clean everything up on first apply()", func() {
			apply()
			Expect(dataplane.IPSetMembers).To(BeEmpty())
		})

		It("should rewrite IP set correctly and clean up temp set", func() {
			ipsets.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
			apply()
			Expect(dataplane.IPSetMembers).To(Equal(map[string]set.Set{
				v4MainIPSetName: set.From("10.0.0.1", "10.0.0.2"),
			}))
			// It shouldn't try to double-delete the temp IP set.
			Expect(dataplane.TriedToDeleteNonExistent).To(BeFalse())
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

			Describe("after another process modifies an IP set", func() {
				BeforeEach(func() {
					dataplane.IPSetMembers[v4MainIPSetName] =
						set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
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
					dataplane.IPSetMembers[v4MainIPSetName] = set.New()
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
				dataplane.IPSetMembers[v4MainIPSetName] =
					set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
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
				Expect(ipsets.ApplyUpdates).To(Panic())
				Expect(dataplane.CumulativeSleep).To(BeNumerically(">", time.Second))
			})
		})
		Describe("with a persistent ipset list failure", func() {
			BeforeEach(func() {
				dataplane.FailAllLists = true
			})
			It("should panic eventually", func() {
				ipsets.QueueResync()
				Expect(ipsets.ApplyUpdates).To(Panic())
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
				Expect(ipsets.ApplyUpdates).To(Panic())
				Expect(dataplane.CumulativeSleep).To(BeNumerically(">", time.Second))
			})
		})
		Describe("with various transient list failures queued up", func() {
			BeforeEach(func() {
				dataplane.IPSetMembers[v4MainIPSetName] =
					set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
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
					dataplane.IPSetMembers[v4MainIPSetName] =
						set.From("10.0.0.1", "10.0.0.3", "10.0.0.4")
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
					apply()
					Expect(dataplane.CumulativeSleep).To(BeNumerically(">", 0))
					dataplane.ExpectMembers(map[string][]string{
						v4MainIPSetName:  {"10.0.0.1", "10.0.0.2"},
						v4MainIPSetName2: {"10.0.0.3", "10.0.0.4"},
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
		Describe("with a write failure to the pipe when writing an IP", describeRetryTests("write-ip"))
		Describe("with an update failure before any upates succeed", describeRetryTests("pre-update"))
		Describe("with an update failure after upates succeed", describeRetryTests("post-update"))
		Describe("with a couple of failures", describeRetryTests("post-update", "pre-update"))
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
			Expect(dataplane.CmdNames).To(ConsistOf("list"))
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
		staleSet := set.New()
		staleSet.Add("10.0.0.1")
		staleSet.Add("10.0.0.2")
		dataplane.IPSetMembers["cali4-unknown"] = staleSet
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
		dataplane.IPSetMembers[v4TempIPSetName] = set.From("10.0.0.1")
		resyncAndApply()

		// Should be cleaned up.
		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
	})
	It("cleanup should ignore non-calico IP sets", func() {
		nonCaliSet := set.New()
		nonCaliSet.Add("10.0.0.1")
		nonCaliSet.Add("10.0.0.2")
		dataplane.IPSetMembers["noncali"] = nonCaliSet

		apply()
		resyncAndApply()
		dataplane.ExpectMembers(map[string][]string{"noncali": v4Members1And2})
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
		Expect(v4VersionConf.OwnsIPSet("cali4-s:abcdef12345_-")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("cali4ts:abcdef12345_-")).To(BeTrue())
	})
	It("should own legacy special case chains", func() {
		Expect(v4VersionConf.OwnsIPSet("felix-masq-ipam-pools")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("felix-all-ipam-pools")).To(BeTrue())
	})
	It("should own legacy chains", func() {
		Expect(v4VersionConf.OwnsIPSet("felix-4-foobar")).To(BeTrue())
		Expect(v4VersionConf.OwnsIPSet("felix-4t-foobar")).To(BeTrue())
	})
	It("should not own chains from another version", func() {
		Expect(v4VersionConf.OwnsIPSet("cali6-s:abcdef12345_-")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("cali6ts:abcdef12345_-")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("felix-6-foobar")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("felix-6t-foobar")).To(BeFalse())
	})
	It("should not own other chains", func() {
		Expect(v4VersionConf.OwnsIPSet("foobar")).To(BeFalse())
		Expect(v4VersionConf.OwnsIPSet("noncali")).To(BeFalse())
	})
})
