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
})
