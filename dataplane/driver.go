// +build !windows

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package dataplane

import (
	"net"
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/dataplane/external"
	"github.com/projectcalico/felix/dataplane/linux"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/logutils"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/libcalico-go/lib/health"
)

func StartDataplaneDriver(configParams *config.Config, healthAggregator *health.HealthAggregator) (DataplaneDriver, *exec.Cmd) {
	if configParams.UseInternalDataplaneDriver {
		log.Info("Using internal (linux) dataplane driver.")
		// Dedicated mark bits for accept and pass actions.  These are long lived bits
		// that we use for communicating between chains.
		markAccept := configParams.NextIptablesMark()
		markPass := configParams.NextIptablesMark()
		// Short-lived mark bits for local calculations within a chain.
		markScratch0 := configParams.NextIptablesMark()
		markScratch1 := configParams.NextIptablesMark()
		log.WithFields(log.Fields{
			"acceptMark":   markAccept,
			"passMark":     markPass,
			"scratch0Mark": markScratch0,
			"scratch1Mark": markScratch1,
		}).Info("Calculated iptables mark bits")
		dpConfig := intdataplane.Config{
			IfaceMonitorConfig: ifacemonitor.Config{
				InterfaceExcludes: configParams.InterfaceExcludes(),
			},
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

				IptablesMarkAccept:   markAccept,
				IptablesMarkPass:     markPass,
				IptablesMarkScratch0: markScratch0,
				IptablesMarkScratch1: markScratch1,

				IPIPEnabled:       configParams.IpInIpEnabled,
				IPIPTunnelAddress: configParams.IpInIpTunnelAddr,

				IptablesLogPrefix:         configParams.LogPrefix,
				EndpointToHostAction:      configParams.DefaultEndpointToHostAction,
				IptablesFilterAllowAction: configParams.IptablesFilterAllowAction,
				IptablesMangleAllowAction: configParams.IptablesMangleAllowAction,

				FailsafeInboundHostPorts:  configParams.FailsafeInboundHostPorts,
				FailsafeOutboundHostPorts: configParams.FailsafeOutboundHostPorts,

				DisableConntrackInvalid: configParams.DisableConntrackInvalidCheck,
			},
			IPIPMTU:                        configParams.IpInIpMtu,
			IptablesRefreshInterval:        configParams.IptablesRefreshInterval,
			RouteRefreshInterval:           configParams.RouteRefreshInterval,
			IPSetsRefreshInterval:          configParams.IpsetsRefreshInterval,
			IptablesPostWriteCheckInterval: configParams.IptablesPostWriteCheckIntervalSecs,
			IptablesInsertMode:             configParams.ChainInsertMode,
			IptablesLockFilePath:           configParams.IptablesLockFilePath,
			IptablesLockTimeout:            configParams.IptablesLockTimeoutSecs,
			IptablesLockProbeInterval:      configParams.IptablesLockProbeIntervalMillis,
			MaxIPSetSize:                   configParams.MaxIpsetSize,
			IgnoreLooseRPF:                 configParams.IgnoreLooseRPF,
			IPv6Enabled:                    configParams.Ipv6Support,
			StatusReportingInterval:        configParams.ReportingIntervalSecs,

			NetlinkTimeout: configParams.NetlinkTimeoutSecs,

			PostInSyncCallback:              func() { logutils.DumpHeapMemoryProfile(configParams) },
			HealthAggregator:                healthAggregator,
			DebugSimulateDataplaneHangAfter: configParams.DebugSimulateDataplaneHangAfter,
		}
		intDP := intdataplane.NewIntDataplaneDriver(dpConfig)
		intDP.Start()

		return intDP, nil
	} else {
		log.WithField("driver", configParams.DataplaneDriver).Info(
			"Using external dataplane driver.")

		return extdataplane.StartExtDataplaneDriver(configParams.DataplaneDriver)
	}
}
