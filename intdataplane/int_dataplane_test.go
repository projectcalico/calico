// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package intdataplane_test

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/intdataplane"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/rules"
)

var _ = Describe("Constructor test", func() {
	var configParams *config.Config
	var dpConfig intdataplane.Config
	BeforeEach(func() {
		configParams = config.New()
		dpConfig = intdataplane.Config{
			RulesConfig: rules.Config{
				WorkloadIfacePrefixes: configParams.InterfacePrefixes(),

				IPSetConfigV4: ipsets.NewIPVersionConfig(
					ipsets.IPFamilyV4,
					rules.IPSetNamePrefix,
					rules.AllHistoricIPSetNamePrefixes,
					rules.LegacyV4IPSetNames,
				),
				IPSetConfigV6: ipsets.NewIPVersionConfig(
					ipsets.IPFamilyV6,
					rules.IPSetNamePrefix,
					rules.AllHistoricIPSetNamePrefixes,
					nil,
				),

				OpenStackSpecialCasesEnabled: configParams.OpenstackActive(),
				OpenStackMetadataIP:          net.ParseIP(configParams.MetadataAddr),
				OpenStackMetadataPort:        uint16(configParams.MetadataPort),

				IptablesMarkAccept: 0x1000000,
				IptablesMarkPass:   0x2000000,

				IPIPEnabled:       configParams.IpInIpEnabled,
				IPIPTunnelAddress: configParams.IpInIpTunnelAddr,

				EndpointToHostAction: configParams.DefaultEndpointToHostAction,
			},
			IPIPMTU: configParams.IpInIpMtu,
		}
	})

	It("should be constructable", func() {
		var dp = intdataplane.NewIntDataplaneDriver(dpConfig)
		Expect(dp).ToNot(BeNil())
	})
})
