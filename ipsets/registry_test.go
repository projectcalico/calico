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

	. "github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/felix/set"
)

var _ = Describe("IP set registry", func() {
	var dataplane *mockDataplane
	var cache *ExistenceCache
	var reg *Registry

	meta := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID,
		Type:    IPSetTypeHashIP,
	}
	v4VersionConf := NewIPVersionConfig(
		IPFamilyV4,
		"cali",
		rules.AllHistoricIPSetNamePrefixes,
		rules.LegacyV4IPSetNames,
	)
	//v6VersionConf := NewIPVersionConfig(IPFamilyV6, "cali", nil, nil)

	BeforeEach(func() {
		dataplane = newMockDataplane()
		cache = NewExistenceCache(dataplane.newCmd)
		reg = NewRegistryWithShims(
			v4VersionConf,
			cache,
			dataplane.newCmd,
		)
	})

	It("mainline: should pend updates until apply is called", func() {
		// Replace call adds an IP that will still be there after subsequent deletes and
		// one that will be deleted.
		reg.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		// Ditto, we add another two IPs, one of which will be removed before the Apply
		// calls.
		reg.AddMembers(ipSetID, []string{"10.0.0.3", "10.0.0.4"})
		// Then delete one from each previous add.
		reg.RemoveMembers(ipSetID, []string{"10.0.0.1", "10.0.0.4"})
		// Dataplane should still be empty.
		dataplane.ExpectMembers(map[string][]string{})
		// Apply updates.
		reg.ApplyDeletions() // No-op
		dataplane.ExpectMembers(map[string][]string{})
		reg.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.2", "10.0.0.3"},
		})
	})
	It("mainline: should ignore IPs of wrong version", func() {
		reg.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2", "fe80::1", "fe80::2"})
		reg.AddMembers(ipSetID, []string{"10.0.0.3", "10.0.0.4", "fe80::2", "fe80::3"})
		reg.RemoveMembers(ipSetID, []string{"10.0.0.1", "10.0.0.4", "fe80::2", "fe80::3"})
		reg.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.2", "10.0.0.3"},
		})
	})
	It("add in its own batch should remove the IP", func() {
		// This checks that the dirty flag is set by the add method.
		reg.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		reg.ApplyUpdates()

		reg.AddMembers(ipSetID, []string{"10.0.0.3", "10.0.0.4"})
		reg.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
		})
	})
	It("remove IP in its own batch should remove the IP", func() {
		// This checks that the dirty flag is set by the remove method.
		reg.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		reg.ApplyUpdates()

		reg.RemoveMembers(ipSetID, []string{"10.0.0.2"})
		reg.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{
			v4MainIPSetName: {"10.0.0.1"},
		})
	})
	It("remove set before apply should be no-op", func() {
		// This checks that the dirty flag is set by the remove method.
		reg.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		reg.RemoveIPSet(ipSetID)
		reg.ApplyDeletions()
		reg.ApplyUpdates()

		dataplane.ExpectMembers(map[string][]string{})
		// Check there were no restore commands.
		Expect(dataplane.Cmds).To(Equal([]CmdIface{
			&listNamesCmd{
				Dataplane: dataplane,
			},
		}))
	})
	It("remove set in its own batch should delete the set", func() {
		// This checks that the dirty flag is set by the remove method.
		reg.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		reg.ApplyDeletions()
		reg.ApplyUpdates()

		reg.RemoveIPSet(ipSetID)
		reg.ApplyDeletions()
		reg.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{})
	})
	It("remove set should be retried on next cleanup", func() {
		reg.AddOrReplaceIPSet(meta, v4Members1And2)
		reg.ApplyDeletions()
		reg.ApplyUpdates()

		dataplane.FailNextDestroy = true
		reg.RemoveIPSet(ipSetID)
		reg.ApplyDeletions()
		reg.ApplyUpdates()
		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})

		reg.AttemptCleanup()
		dataplane.ExpectMembers(map[string][]string{})
	})
	It("cleanup should remove unknown IP sets", func() {
		staleSet := set.New()
		staleSet.Add("10.0.0.1")
		staleSet.Add("10.0.0.2")
		dataplane.IPSetMembers["cali4-unknown"] = staleSet
		dataplane.IPSetMembers["cali4tunknown"] = staleSet
		reg.AddOrReplaceIPSet(meta, v4Members1And2)

		reg.ApplyDeletions()
		reg.ApplyUpdates()
		reg.AttemptCleanup()

		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
	})
	It("cleanup should ignore active IP sets", func() {
		reg.AddOrReplaceIPSet(meta, v4Members1And2)
		reg.ApplyDeletions()
		reg.ApplyUpdates()
		reg.AttemptCleanup()

		dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
	})
	It("cleanup should ignore non-calico IP sets", func() {
		nonCaliSet := set.New()
		nonCaliSet.Add("10.0.0.1")
		nonCaliSet.Add("10.0.0.2")
		dataplane.IPSetMembers["noncali"] = nonCaliSet

		reg.ApplyDeletions()
		reg.ApplyUpdates()
		reg.AttemptCleanup()

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
