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
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/nftables"
	. "github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Maps with empty data plane", func() {
	var s *Maps
	var f *fakeNFT

	var chainRefs map[string]int
	increfChain := func(chain string) {
		chainRefs[chain]++
	}
	decrefChain := func(chain string) {
		chainRefs[chain]--
		if chainRefs[chain] == 0 {
			delete(chainRefs, chain)
		}
	}

	BeforeEach(func() {
		f = NewFake(knftables.IPv4Family, "calico")
		ipv := ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil)

		// Reset chain references.
		chainRefs = make(map[string]int)

		s = NewMaps(ipv, f, increfChain, decrefChain, logutils.NewSummarizer("test loop"))
	})

	It("should generate MapUpdates on empty state)", func() {
		Expect(s.MapUpdates()).To(Equal(&MapUpdates{
			MapToAddedMembers:   map[string]set.Set[MapMember]{},
			MapToDeletedMembers: map[string]set.Set[MapMember]{},
		}))
	})

	It("should incref / decref chains correctly", func() {
		// Create a number of different maps.
		m1 := nftables.MapMetadata{Name: "m1", Type: nftables.MapTypeInterfaceMatch}
		m2 := nftables.MapMetadata{Name: "m2", Type: nftables.MapTypeInterfaceMatch}
		m3 := nftables.MapMetadata{Name: "m3", Type: nftables.MapTypeInterfaceMatch}
		s.AddOrReplaceMap(m1, map[string][]string{"cali1234": {"jump chain1234"}})
		s.AddOrReplaceMap(m2, map[string][]string{"caliabcd": {"jump chainabcd"}})
		s.AddOrReplaceMap(m3, map[string][]string{"caliefgh": {"jump chainefgh"}})

		Expect(chainRefs).To(Equal(map[string]int{
			"chain1234": 1,
			"chainabcd": 1,
			"chainefgh": 1,
		}))
		upd := s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(3))
		Expect(upd.MapToDeletedMembers).To(HaveLen(0))
		Expect(upd.MapsToCreate).To(HaveLen(3))
		Expect(upd.MapsToDelete).To(HaveLen(0))
		Expect(upd.MembersToAdd).To(HaveLen(3))
		Expect(upd.MembersToDel).To(HaveLen(0))

		// Simulate a successful apply.
		s.FinishMapUpdates(upd)

		// Verify internal state is updated - next update should do nothing.
		Expect(s.MapUpdates()).To(Equal(&MapUpdates{
			MapToAddedMembers:   map[string]set.Set[MapMember]{},
			MapToDeletedMembers: map[string]set.Set[MapMember]{},
		}))

		// Send new interfaces to map1, both adding a new member and updating an existing one.
		s.AddOrReplaceMap(m1, map[string][]string{
			"cali1234": {"jump newchain1234"},
			"cali5678": {"jump chain5678"},
		})

		Expect(chainRefs).To(Equal(map[string]int{
			"chain5678":    1,
			"newchain1234": 1,
			"chainabcd":    1,
			"chainefgh":    1,
		}))

		// We should see a delete for the old member, as well as two new adds.
		upd = s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(1))
		Expect(upd.MapToDeletedMembers).To(HaveLen(1))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(0))
		Expect(upd.MembersToAdd).To(HaveLen(2))
		Expect(upd.MembersToDel).To(HaveLen(1))

		// Simulate a successful apply and verify state is cleared.
		s.FinishMapUpdates(upd)
		Expect(s.MapUpdates()).To(Equal(&MapUpdates{
			MapToAddedMembers:   map[string]set.Set[MapMember]{},
			MapToDeletedMembers: map[string]set.Set[MapMember]{},
		}))

		// Delete a map.
		s.RemoveMap(m2.Name)

		Expect(chainRefs).To(Equal(map[string]int{
			"chain5678":    1,
			"newchain1234": 1,
			"chainefgh":    1,
		}))

		// We should see a delete for the map and all its members.
		upd = s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(0))
		Expect(upd.MapToDeletedMembers).To(HaveLen(1))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(1))
		Expect(upd.MembersToAdd).To(HaveLen(0))
		Expect(upd.MembersToDel).To(HaveLen(1))

		// Simulate a successful apply and verify state is cleared.
		s.FinishMapUpdates(upd)
		Expect(s.MapUpdates()).To(Equal(&MapUpdates{
			MapToAddedMembers:   map[string]set.Set[MapMember]{},
			MapToDeletedMembers: map[string]set.Set[MapMember]{},
		}))

		// Delete a map member.
		s.AddOrReplaceMap(m1, map[string][]string{"cali1234": {"jump newchain1234"}})

		Expect(chainRefs).To(Equal(map[string]int{
			"newchain1234": 1,
			"chainefgh":    1,
		}))

		// We should see a delete for the old member, but no adds.
		upd = s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(0))
		Expect(upd.MapToDeletedMembers).To(HaveLen(1))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(0))
		Expect(upd.MembersToAdd).To(HaveLen(0))
		Expect(upd.MembersToDel).To(HaveLen(1))
	})

	It("should synchronize with the dataplane", func() {
		// Create a map - both in nftables and in the MapsDataplane.
		m1 := nftables.MapMetadata{Name: "m1", Type: nftables.MapTypeInterfaceMatch}
		mapElements := map[string][]string{"cali1234": {"jump chain1234"}}
		s.AddOrReplaceMap(m1, mapElements)
		s.FinishMapUpdates(s.MapUpdates())
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		addMapToTx(tx, m1, mapElements)
		Expect(f.Run(context.TODO(), tx)).NotTo(HaveOccurred())

		// Resync with dataplane.
		Expect(s.LoadDataplaneState()).NotTo(HaveOccurred())

		// Should be no work to do.
		Expect(s.MapUpdates()).To(Equal(&MapUpdates{
			MapToAddedMembers:   map[string]set.Set[MapMember]{},
			MapToDeletedMembers: map[string]set.Set[MapMember]{},
		}))

		// Modify the map in the dataplane to add an additional element.
		tx = f.NewTransaction()
		tx.Add(&knftables.Chain{Name: "chain5678"})
		tx.Add(&knftables.Element{
			Map:   m1.Name,
			Key:   []string{"cali5678"},
			Value: []string{"jump chain5678"},
		})
		Expect(f.Run(context.TODO(), tx)).NotTo(HaveOccurred())

		// Resync with dataplane. We should now detect the new element and queue it for removal.
		Expect(s.LoadDataplaneState()).NotTo(HaveOccurred())
		upd := s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(0))
		Expect(upd.MapToDeletedMembers).To(HaveLen(1))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(0))
		Expect(upd.MembersToAdd).To(HaveLen(0))
		Expect(upd.MembersToDel).To(HaveLen(1))
		s.FinishMapUpdates(upd)

		// Remove all elements from the map in the dataplane.
		tx = f.NewTransaction()
		tx.Delete(&knftables.Element{
			Map:   m1.Name,
			Key:   []string{"cali1234"},
			Value: []string{"jump chain1234"},
		})
		tx.Delete(&knftables.Element{
			Map:   m1.Name,
			Key:   []string{"cali5678"},
			Value: []string{"jump chain5678"},
		})

		// Add a bogus map.
		tx.Add(&knftables.Map{
			Name: "bogus",
			Type: "ifname : verdict",
		})
		Expect(f.Run(context.TODO(), tx)).NotTo(HaveOccurred())

		// A resync should fix both the map and the elements.
		Expect(s.LoadDataplaneState()).NotTo(HaveOccurred())
		upd = s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(1))
		Expect(upd.MapToDeletedMembers).To(HaveLen(0))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(1))
		Expect(upd.MembersToAdd).To(HaveLen(1))
		Expect(upd.MembersToDel).To(HaveLen(0))
		s.FinishMapUpdates(upd)
	})

	It("should resync with a large number of maps", func() {
		// Create a large number of sets - larger than the number of gorooutines we limit
		// ourselves to in the resync code.
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		for i := 0; i < 200; i++ {
			tx.Add(&knftables.Map{
				Name: fmt.Sprintf("map-%d", i),
				Type: "ifname : verdict",
			})
		}
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		// Trigger a resync.
		Expect(s.LoadDataplaneState()).NotTo(HaveOccurred())

		// Expect queued deletions for all the maps.
		upd := s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(0))
		Expect(upd.MapToDeletedMembers).To(HaveLen(0))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(200))
		Expect(upd.MembersToAdd).To(HaveLen(0))
		Expect(upd.MembersToDel).To(HaveLen(0))
		s.FinishMapUpdates(upd)
	})

	It("should handle unexpected maps with types that are not supported", func() {
		// Create a Map direclty in the dataplane, with a type that is not supported by the MapsDataplane.
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Map{
			Name: "cali40unsupported-map",
			Type: "ipv4_addr . ipv4_addr : verdict",
		})
		tx.Add(&knftables.Chain{Name: "chain1234"})
		tx.Add(&knftables.Element{
			Map:   "cali40unsupported-map",
			Key:   []string{"1.2.3.4", "10.0.0.1"},
			Value: []string{"jump chain1234"},
		})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		// Trigger a resync. We should delete the unexpected map.
		Expect(s.LoadDataplaneState()).NotTo(HaveOccurred())

		// Expect the set to be deleted.
		upd := s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(0))
		Expect(upd.MapToDeletedMembers).To(HaveLen(1))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(1))
		Expect(upd.MembersToAdd).To(HaveLen(0))
		Expect(upd.MembersToDel).To(HaveLen(1))
		s.FinishMapUpdates(upd)
	})

	It("should handle expected maps with an unexpected and unsupported type", func() {
		// Create Map in the dataplane with an unexpected type.
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Map{
			Name: "unsupported-map",
			Type: "ipv4_addr . ipv4_addr : verdict",
		})
		tx.Add(&knftables.Chain{Name: "chain1234"})
		tx.Add(&knftables.Element{
			Map:   "unsupported-map",
			Key:   []string{"1.2.3.4", "10.0.0.1"},
			Value: []string{"jump chain1234"},
		})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		// Create the same IP set via the MapsDataplane object with a supported type.
		meta := MapMetadata{Name: "unsupported-map", Type: MapTypeInterfaceMatch}
		s.AddOrReplaceMap(meta, nil)

		// Load the dataplane state. We should delete the unexpected map.
		Expect(s.LoadDataplaneState()).NotTo(HaveOccurred())

		// Expect members to be correct. We should remove the unexpected members despite not knowing the type.
		// NOTE: We currently have no way to know or change the type of the map via knftables.
		upd := s.MapUpdates()
		Expect(upd.MapToAddedMembers).To(HaveLen(0))
		Expect(upd.MapToDeletedMembers).To(HaveLen(1))
		Expect(upd.MapsToCreate).To(HaveLen(0))
		Expect(upd.MapsToDelete).To(HaveLen(0))
		Expect(upd.MembersToAdd).To(HaveLen(0))
		Expect(upd.MembersToDel).To(HaveLen(1))
		s.FinishMapUpdates(upd)
	})
})

func addMapToTx(tx *knftables.Transaction, m nftables.MapMetadata, elements map[string][]string) {
	tx.Add(&knftables.Map{
		Name: m.Name,
		Type: "ifname : verdict",
	})
	for k, v := range elements {
		// Add the referenced chain.
		tx.Add(&knftables.Chain{Name: strings.Split(v[0], " ")[1]})

		// Add the map element.
		tx.Add(&knftables.Element{
			Map:   m.Name,
			Key:   []string{k},
			Value: v,
		})
	}
}
