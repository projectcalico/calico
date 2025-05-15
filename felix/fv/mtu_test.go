// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ VXLAN topology before adding host IPs to IP sets", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
	)

	expectMTU := func(mtu int) {
		for _, felix := range tc.Felixes {
			EventuallyWithOffset(1, func() string {
				out, _ := felix.ExecOutput("cat", "/var/lib/calico/mtu")
				return strings.TrimSpace(out)
			}, "60s", "500ms").Should(Equal(fmt.Sprint(mtu)))
		}
		if BPFMode() {
			felix := tc.Felixes[0]
			EventuallyWithOffset(1, func() string {
				out, _ := felix.ExecOutput("ip", "link", "show", "dev", "bpfin.cali")
				return out
			}, "5s", "500ms").Should(ContainSubstring(fmt.Sprintf("mtu %d", mtu)))
			EventuallyWithOffset(1, func() string {
				out, _ := felix.ExecOutput("ip", "link", "show", "dev", "bpfout.cali")
				return out
			}, "5s", "500ms").Should(ContainSubstring(fmt.Sprintf("mtu %d", mtu)))
		}
	}

	vxlanOverhead := func(ipv6 bool) int {
		if ipv6 {
			return 70
		}
		return 50
	}

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("ip", "link")
				if BPFMode() {
					felix.Exec("calico-bpf", "ifstate", "dump")
				}
			}
			infra.DumpErrorData()
		}
		tc.Stop()
		infra.Stop()
	})

	for _, ipv6 := range []bool{true, false} {
		enableIPv6 := ipv6
		Describe(fmt.Sprintf("IPv6 enabled: %v", enableIPv6), func() {
			Context("with default MTU interface pattern", func() {
				BeforeEach(func() {
					infra = getInfra()
					topologyOptions := infrastructure.DefaultTopologyOptions()
					topologyOptions.DelayFelixStart = true
					topologyOptions.VXLANMode = api.VXLANModeAlways
					topologyOptions.VXLANStrategy = infrastructure.NewDefaultVXLANStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
					topologyOptions.IPIPMode = api.IPIPModeNever
					topologyOptions.EnableIPv6 = enableIPv6

					// Need n>1 or the infra won't set up IP pools!
					tc, client = infrastructure.StartNNodeTopology(2, topologyOptions, infra)
				})

				It("should get the MTU from the main interface", func() {
					// Set a distinctive MTU on the main interface.
					for _, f := range tc.Felixes {
						f.Exec("ip", "link", "set", "dev", "eth0", "mtu", "1312")
					}
					tc.TriggerDelayedStart()
					expectMTU(1312 - vxlanOverhead(enableIPv6))
				})

				addDummyNIC := func(f *infrastructure.Felix, up bool) {
					f.Exec("ip", "link", "add", "type", "dummy")
					f.Exec("ip", "link", "set", "dev", "dummy0", "mtu", "1300")
					f.Exec("ip", "link", "set", "name", "eth1", "dummy0")
					if up {
						f.Exec("ip", "link", "set", "dev", "eth1", "up")
					}
				}
				It("should ignore a secondary interface that is down", func() {
					// Set a distinctive MTU on the main interface.
					for _, f := range tc.Felixes {
						f.Exec("ip", "link", "set", "dev", "eth0", "mtu", "1312")
						addDummyNIC(f, false)
					}
					tc.TriggerDelayedStart()
					expectMTU(1312 - vxlanOverhead(enableIPv6))
				})
				It("should consider a secondary interface that is up", func() {
					// Set a distinctive MTU on the main interface.
					for _, f := range tc.Felixes {
						f.Exec("ip", "link", "set", "dev", "eth0", "mtu", "1312")
						addDummyNIC(f, true)
					}
					tc.TriggerDelayedStart()
					expectMTU(1300 - vxlanOverhead(enableIPv6))
				})
			})

			Context("with mismatched MTU interface pattern", func() {
				BeforeEach(func() {
					infra = getInfra()
					topologyOptions := infrastructure.DefaultTopologyOptions()
					topologyOptions.VXLANMode = api.VXLANModeAlways
					topologyOptions.VXLANStrategy = infrastructure.NewDefaultVXLANStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
					topologyOptions.IPIPMode = api.IPIPModeNever
					topologyOptions.EnableIPv6 = enableIPv6

					// Configure the interface pattern so that it doesn't match any host interfaces.
					topologyOptions.ExtraEnvVars["FELIX_MTUIFACEPATTERN"] = "foo"

					tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

					// Wait until the vxlan device appears.
					Eventually(func() error {
						for i, f := range tc.Felixes {
							out, err := f.ExecOutput("ip", "link")
							if err != nil {
								return err
							}
							if strings.Contains(out, "vxlan.calico") {
								continue
							}
							return fmt.Errorf("felix %d has no vxlan device", i)
						}
						return nil
					}, "30s", "100ms").ShouldNot(HaveOccurred())
				})

				It("should configure MTU correctly based on FelixConfiguration", func() {
					// We should NOT detect the primary interface's MTU of 1500, and instead default
					// to 1460 due to the mismatched regex. Since VXLAN is enabled, we expect 1460 minus
					// the VXLAN overhead of 50 in case of IPv4 or 70 in case of IPv6 to show up in the MTU file.
					vxlanDisabledMtu := 1460
					vxlanEnabledMtu := vxlanDisabledMtu - vxlanOverhead(enableIPv6)
					expectMTU(vxlanEnabledMtu)

					// Disable VXLAN. We should expect the MTU to change, but still based on the default 1460.
					// Create a default FelixConfiguration
					fc := api.NewFelixConfiguration()
					fc.Name = "default"
					f := false
					fc.Spec.VXLANEnabled = &f
					_, err := client.FelixConfigurations().Create(context.Background(), fc, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					// To disable vxlan for ipv6, set VXLANModeNever on the IPv6 pool
					if enableIPv6 {
						poolV6, err := client.IPPools().Get(context.Background(), infrastructure.DefaultIPv6PoolName, options.GetOptions{})
						Expect(err).NotTo(HaveOccurred())
						poolV6.Spec.VXLANMode = api.VXLANModeNever
						_, err = client.IPPools().Update(context.Background(), poolV6, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
					}

					// It should now have an MTU of 1460 since there is no encap.
					expectMTU(vxlanDisabledMtu)
				})

				It("should configure MTU correctly based on IP pools", func() {
					// We should NOT detect the primary interface's MTU of 1500, and instead default
					// to 1460 due to the mismatched regex. Since VXLAN is enabled, we expect 1460
					// minus the VXLAN overhead of 50 in case of IPv4 or 70 in case of IPv6 to show up in the MTU file.
					vxlanDisabledMtu := 1460
					vxlanEnabledMtu := vxlanDisabledMtu - vxlanOverhead(enableIPv6)
					expectMTU(vxlanEnabledMtu)

					// Unset VXLAN on FelixConfiguration. We should expect the MTU not to change, since the VXLAN encap is set in the default IPPool.
					fc := api.NewFelixConfiguration()
					fc.Name = "default"
					fc.Spec.VXLANEnabled = nil
					_, err := client.FelixConfigurations().Create(context.Background(), fc, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					// It should still have an MTU of 1410 (or 1390 for IPv6) since the VXLAN encap is set in the default IPPool.

					expectMTU(vxlanEnabledMtu)

					// Set VXLANModeNever on the default IP pool(s)
					pool, err := client.IPPools().Get(context.Background(), infrastructure.DefaultIPPoolName, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					pool.Spec.VXLANMode = api.VXLANModeNever
					_, err = client.IPPools().Update(context.Background(), pool, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					if enableIPv6 {
						poolV6, err := client.IPPools().Get(context.Background(), infrastructure.DefaultIPv6PoolName, options.GetOptions{})
						Expect(err).NotTo(HaveOccurred())
						poolV6.Spec.VXLANMode = api.VXLANModeNever
						_, err = client.IPPools().Update(context.Background(), poolV6, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
					}

					// It should now have an MTU of 1460 since there is no encap.
					expectMTU(vxlanDisabledMtu)
				})
			})
		})
	}
})
