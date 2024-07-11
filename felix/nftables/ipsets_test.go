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
})
