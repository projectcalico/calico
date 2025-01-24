// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ut_test

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/cttestdata"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

func TestBPFProgLivenessScanner(t *testing.T) {
	for _, tc := range cttestdata.CTCleanupTests {
		t.Run(tc.Description, func(t *testing.T) {
			runCTCleanupTest(t, tc)
		})
	}
}

func runCTCleanupTest(t *testing.T, tc cttestdata.CTCleanupTest) {
	scanner := setUpConntrackScanTest(t)

	// Load the starting conntrack state.
	for k, v := range tc.KVs {
		err := ctMap.Update(k.AsBytes(), v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	// Run the scanner, mocking out the current time to match the conntrack state.
	err := scanner.RunBPFExpiryProgram(conntrack.WithStartTime(uint64(cttestdata.Now)))
	Expect(err).NotTo(HaveOccurred(), "Failed to run BPFProgLivenessScanner")

	// Check that the expected entries were deleted.
	deletedEntries := calculateDeletedEntries(tc, ctMap)
	Expect(deletedEntries).To(ConsistOf(tc.ExpectedDeletions),
		"Scan() did not delete the expected entries")
}

func setUpConntrackScanTest(t *testing.T) *conntrack.BPFProgLivenessScanner {
	RegisterTestingT(t)
	scanner, err := conntrack.NewBPFProgLivenessScanner(
		4, conntrack.DefaultTimeouts(), conntrack.BPFLogLevelDebug,
		nil, "Disabled")
	Expect(err).NotTo(HaveOccurred(), "Failed to create BPFProgLivenessScanner")
	t.Cleanup(func() {
		err := scanner.Close()
		Expect(err).NotTo(HaveOccurred(), "Failed to close BPFProgLivenessScanner")
	})

	clearCTMap := func() {
		resetMap(ctMap)
	}
	clearCTMap()          // Make sure we start with an empty map.
	t.Cleanup(clearCTMap) // Make sure we leave a clean map.
	return scanner
}

func calculateDeletedEntries(tc cttestdata.CTCleanupTest, ctMap maps.Map) []conntrack.Key {
	var deletedEntries []conntrack.Key
	for k := range tc.KVs {
		_, err := ctMap.Get(k.AsBytes())
		if maps.IsNotExists(err) {
			deletedEntries = append(deletedEntries, k)
		} else {
			Expect(err).NotTo(HaveOccurred(), "unexpected error from map lookup")
		}
	}
	return deletedEntries
}
