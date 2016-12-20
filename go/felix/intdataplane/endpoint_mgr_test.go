// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/felix/go/felix/config"
	"github.com/projectcalico/felix/go/felix/intdataplane"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/rules"
	"net"
)

var configParams = config.New()

var dpConfig = intdataplane.Config{
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

		// TODO(smc) honour config of iptables mark marks.
		IptablesMarkAccept:   0x1,
		IptablesMarkNextTier: 0x2,

		IPIPEnabled:       configParams.IpInIpEnabled,
		IPIPTunnelAddress: configParams.IpInIpTunnelAddr,

		ActionOnDrop:         configParams.DropActionOverride,
		EndpointToHostAction: configParams.DefaultEndpointToHostAction,
	},
	IPIPMTU: configParams.IpInIpMtu,
}

var driver = intdataplane.NewIntDataplaneDriver(dpConfig)
