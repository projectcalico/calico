// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package nftables_test

import (
	"context"
	"fmt"

	"sigs.k8s.io/knftables"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	. "github.com/projectcalico/calico/felix/nftables"
)

var _ = Describe("IPSets with empty data plane", func() {
	var s *IPSets
	var f *fakeNFT
	BeforeEach(func() {
		f = NewFake(knftables.IPv4Family, "calico")
		ipv := ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil)
		s = NewIPSets(ipv, f, logutils.NewSummarizer("test loop"))
	})

	It("should Apply() on an empty state)", func() {
		Expect(s.ApplyUpdates).NotTo(Panic())
	})

	It("should handle a failed ListElements call", func() {
		// Create a number of different sets.
		m1 := ipsets.IPSetMetadata{SetID: "m1", Type: ipsets.IPSetTypeHashIP}
		m2 := ipsets.IPSetMetadata{SetID: "m2", Type: ipsets.IPSetTypeHashIP}
		m3 := ipsets.IPSetMetadata{SetID: "m3", Type: ipsets.IPSetTypeHashIP}
		s.AddOrReplaceIPSet(m1, []string{"10.0.0.1"})
		s.AddOrReplaceIPSet(m2, []string{"10.0.0.2"})
		s.AddOrReplaceIPSet(m3, []string{"10.0.0.3"})
		s.ApplyUpdates()

		// Modifiy each set out-of-band.
		tx := f.NewTransaction()
		tx.Delete(&knftables.Element{
			Set: "cali40m1",
			Key: []string{"10.0.0.1"},
		})
		tx.Add(&knftables.Element{
			Set: "cali40m2",
			Key: []string{"11.11.11.11"},
		})
		tx.Add(&knftables.Element{
			Set: "cali40m3",
			Key: []string{"11.11.11.11"},
		})
		Expect(f.Run(context.Background(), tx)).To(Succeed())

		// Set an error to occur on the next ListElements call for m2.
		f.ListElementsErrors = map[string]error{"cali40m2": fmt.Errorf("test error")}

		// Trigger a resync, which should fix the out-of-band modifications.
		f.Reset()
		s.QueueResync()
		s.ApplyUpdates()

		// Expect all errors to have been executed.
		Expect(f.ListElementsErrors).To(HaveLen(0))

		// Expect the sets to be in the correct state after the resync fails and then retries.
		Expect(f.transactions).To(HaveLen(1))
		elems, err := f.ListElements(context.TODO(), "set", "cali40m2")
		Expect(err).NotTo(HaveOccurred())
		Expect(elems).To(HaveLen(1))
	})

	// Add base test cases to test the programing of simple IP sets.
	for _, t := range []ipsets.IPSetType{ipsets.IPSetTypeHashIP, ipsets.IPSetTypeHashNet, ipsets.IPSetTypeHashIPPort, ipsets.IPSetTypeHashNetNet} {
		It(fmt.Sprintf("should program IP sets of type %s", t), func() {
			meta := ipsets.IPSetMetadata{SetID: "test", Type: t}
			s.AddOrReplaceIPSet(meta, []string{})
			Expect(s.ApplyUpdates).NotTo(Panic())
			sets, err := f.List(context.Background(), "sets")
			Expect(err).NotTo(HaveOccurred())
			Expect(sets).To(HaveLen(1))
		})
	}

	It("should resync with the dataplane", func() {
		// Create an IP set in the dataplane via the IPSets object.
		meta := ipsets.IPSetMetadata{SetID: "test", Type: ipsets.IPSetTypeHashIP}
		s.AddOrReplaceIPSet(meta, []string{"10.0.0.1", "10.0.0.2"})
		Expect(s.ApplyUpdates).NotTo(Panic())

		// Create an IP set in the dataplane directly.
		tx := f.NewTransaction()
		tx.Add(&knftables.Set{
			Name: "extra-set",
			Type: "ipv4_addr",
		})
		// Also remove one of the members from the "good" set.
		tx.Delete(&knftables.Element{
			Set: "cali40test",
			Key: []string{"10.0.0.2"},
		})
		// Also add an unexpected element to the "good" set.
		tx.Add(&knftables.Element{
			Set: "cali40test",
			Key: []string{"192.168.0.0"},
		})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		// Trigger a resync.
		s.QueueResync()
		Expect(s.ApplyUpdates).NotTo(Panic())
		Expect(s.ApplyDeletions()).To(BeFalse())

		// We expect:
		// - The IP set created via the IPSets object to still exist.
		// - The IP set created directly in the dataplane to be deleted.
		// - The unexpected element to be removed.
		// - The missing element to be added back.
		sets, err := f.List(context.Background(), "sets")
		Expect(err).NotTo(HaveOccurred())
		Expect(sets).To(HaveLen(1))

		// Check the contents of the set.
		elements, err := f.ListElements(context.Background(), "set", "cali40test")
		Expect(err).NotTo(HaveOccurred())
		Expect(elements).To(ConsistOf(
			&knftables.Element{Set: "cali40test", Key: []string{"10.0.0.1"}},
			&knftables.Element{Set: "cali40test", Key: []string{"10.0.0.2"}},
		))
	})

	It("should handle unexpected sets with types that are not supported", func() {
		// Create an IP set direclty in the dataplane, with a type that is not supported by the IPSets object.
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Set{
			Name: "cali40unsupported-set",
			Type: "ipv4_addr . ipv4_addr . inet_service . inet_service",
		})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		// Trigger a resync. We should delete the unexpected set.
		s.QueueResync()
		Expect(s.ApplyUpdates).NotTo(Panic())
		Expect(s.ApplyDeletions()).To(BeFalse())

		// We expect the set to be deleted.
		sets, err := f.List(context.Background(), "sets")
		Expect(err).NotTo(HaveOccurred())
		Expect(sets).To(HaveLen(0))
	})

	It("should handle expected sets with an unexpected and unsupported type", func() {
		// Create an IP set in the dataplane with an unexpected type.
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Set{
			Name: "cali40unsupported-set",
			Type: "ipv4_addr . ipv4_addr . inet_service . inet_service",
		})
		tx.Add(&knftables.Element{
			Set: "cali40unsupported-set",
			Key: []string{"11.0.0.1", "11.0.0.2", "tcp:80", "tcp:443"},
		})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		// Create the same IP set via the IPSets object with a supported type.
		meta := ipsets.IPSetMetadata{SetID: "unsupported-set", Type: ipsets.IPSetTypeHashIP}
		s.AddOrReplaceIPSet(meta, []string{"10.0.0.1"})

		// Apply.
		s.QueueResync()
		Expect(s.ApplyUpdates).NotTo(Panic())

		// Expect the set to exist.
		sets, err := f.List(context.Background(), "sets")
		Expect(err).NotTo(HaveOccurred())
		Expect(sets).To(HaveLen(1))

		// TODO: We have no means to check the set type without changes to knftables.

		// Expect members to be correct. We should have removed the unexpected members despite not knowing the type.
		elements, err := f.ListElements(context.Background(), "set", "cali40unsupported-set")
		Expect(err).NotTo(HaveOccurred())
		Expect(elements).To(ConsistOf(
			&knftables.Element{Set: "cali40unsupported-set", Key: []string{"10.0.0.1"}},
		))
	})

	It("should program a hash:net,net IP set", func() {
		meta := ipsets.IPSetMetadata{SetID: "test", Type: ipsets.IPSetTypeHashNetNet}
		s.AddOrReplaceIPSet(meta, []string{"10.0.0.0/32,11.0.0.0/32"})
		Expect(s.ApplyUpdates).NotTo(Panic())
		sets, err := f.List(context.Background(), "sets")
		Expect(err).NotTo(HaveOccurred())
		Expect(sets).To(Equal([]string{"cali40test"}))

		members, err := f.ListElements(context.Background(), "set", "cali40test")
		Expect(err).NotTo(HaveOccurred())
		Expect(members).To(HaveLen(1))
		Expect(members[0].Key).To(Equal([]string{"10.0.0.0", "11.0.0.0"}))
	})
})
