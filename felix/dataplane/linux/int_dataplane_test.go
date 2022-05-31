// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/config"
	intdataplane "github.com/projectcalico/calico/felix/dataplane/linux"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

var _ = Describe("Constructor test", func() {
	var configParams *config.Config
	var dpConfig intdataplane.Config
	var healthAggregator *health.HealthAggregator
	kubernetesProvider := config.ProviderNone
	routeSource := "CalicoIPAM"
	var wireguardEncryptHostTraffic bool

	JustBeforeEach(func() {
		configParams = config.New()
		_, err := configParams.UpdateFrom(map[string]string{"InterfaceExclude": "/^kube.*/,/veth/,eth2"}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())
		dpConfig = intdataplane.Config{
			FloatingIPsEnabled: true,
			IfaceMonitorConfig: ifacemonitor.Config{
				InterfaceExcludes: configParams.InterfaceExclude,
				ResyncInterval:    configParams.RouteRefreshInterval,
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

				IptablesMarkAccept:   0x1000000,
				IptablesMarkPass:     0x2000000,
				IptablesMarkScratch0: 0x4000000,
				IptablesMarkScratch1: 0x8000000,
				IptablesMarkEndpoint: 0x000ff00,

				IPIPEnabled:       configParams.Encapsulation.IPIPEnabled,
				IPIPTunnelAddress: configParams.IpInIpTunnelAddr,

				EndpointToHostAction:      configParams.DefaultEndpointToHostAction,
				IptablesFilterAllowAction: configParams.IptablesFilterAllowAction,
				IptablesMangleAllowAction: configParams.IptablesMangleAllowAction,
			},
			IPIPMTU:          configParams.IpInIpMtu,
			HealthAggregator: healthAggregator,

			MTUIfacePattern: regexp.MustCompile(".*"),

			LookPathOverride: func(file string) (string, error) {
				return file, nil
			},

			KubernetesProvider: kubernetesProvider,
			RouteSource:        routeSource,
			Wireguard: wireguard.Config{
				EncryptHostTraffic: wireguardEncryptHostTraffic,
			},
		}
	})

	It("should be constructable", func() {
		dp := intdataplane.NewIntDataplaneDriver(dpConfig)
		Expect(dp).ToNot(BeNil())
	})

	Context("with health aggregator", func() {
		BeforeEach(func() {
			healthAggregator = health.NewHealthAggregator()
		})

		It("should be constructable", func() {
			dp := intdataplane.NewIntDataplaneDriver(dpConfig)
			Expect(dp).ToNot(BeNil())
		})
	})

	Context("with Wireguard on AKS", func() {
		BeforeEach(func() {
			kubernetesProvider = config.ProviderAKS
			routeSource = "WorkloadIPs"
			wireguardEncryptHostTraffic = true
		})

		It("should set the correct MTU", func() {
			intdataplane.ConfigureDefaultMTUs(1500, &dpConfig)
			Expect(dpConfig.Wireguard.MTU).To(Equal(1340))
		})
	})

	Context("with Wireguard on non-managed provider", func() {
		BeforeEach(func() {
			kubernetesProvider = config.ProviderNone
			routeSource = "CalicoIPAM"
		})

		It("should set the correct MTU", func() {
			intdataplane.ConfigureDefaultMTUs(1500, &dpConfig)
			Expect(dpConfig.Wireguard.MTU).To(Equal(1440))
		})
	})
})
