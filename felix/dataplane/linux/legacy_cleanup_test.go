// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/iptables/testutils"
)

var _ = Describe("Legacy iptables cleanup tables", func() {
	featureDetector := environment.NewFeatureDetector(nil)

	var realModulesLoaded func(ipVersion uint8) bool

	BeforeEach(func() {
		realModulesLoaded = environment.LegacyIPTablesModulesLoaded
		environment.LegacyIPTablesModulesLoaded = func(ipVersion uint8) bool {
			return true
		}
	})

	AfterEach(func() {
		environment.LegacyIPTablesModulesLoaded = realModulesLoaded
	})

	It("sweeps all four tables when the legacy binaries are there", func() {
		opts := iptables.TableOptions{LookPathOverride: testutils.LookPathAll}
		tables := legacyIPTablesCleanupTables(4, featureDetector, opts, opts)

		var names []string
		for _, t := range tables {
			names = append(names, t.Name())
			Expect(t.IPVersion()).To(BeNumerically("==", 4))
		}
		Expect(names).To(ConsistOf("filter", "mangle", "raw", "nat"))
	})

	// FindBestBinary falls back to the default iptables binary, which on a modern distro drives
	// nftables. Building the tables anyway would sweep the backend Felix is programming.
	It("builds nothing when the legacy binaries are missing", func() {
		opts := iptables.TableOptions{LookPathOverride: testutils.LookPathNoLegacy}
		Expect(legacyIPTablesCleanupTables(4, featureDetector, opts, opts)).To(BeEmpty())
		Expect(legacyIPTablesCleanupTables(6, featureDetector, opts, opts)).To(BeEmpty())
	})

	// Felix would be programming the legacy backend itself, via the plain iptables binaries.
	It("builds nothing when the nft binaries are missing", func() {
		opts := iptables.TableOptions{LookPathOverride: testutils.LookPathNoNFT}
		Expect(legacyIPTablesCleanupTables(4, featureDetector, opts, opts)).To(BeEmpty())
		Expect(legacyIPTablesCleanupTables(6, featureDetector, opts, opts)).To(BeEmpty())
	})

	// Reading the legacy tables would autoload the modules onto a pure-nftables node.
	It("builds nothing when the legacy modules aren't loaded", func() {
		environment.LegacyIPTablesModulesLoaded = func(ipVersion uint8) bool {
			return false
		}
		opts := iptables.TableOptions{LookPathOverride: testutils.LookPathAll}
		Expect(legacyIPTablesCleanupTables(4, featureDetector, opts, opts)).To(BeEmpty())
	})
})
