// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ endpoint-to-host-action tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
		w      [2]*workload.Workload
		hostW  [2]*workload.Workload

		cc *connectivity.Checker
	)

	BeforeEach(func() {
		if NFTMode() {
			Skip("TODO: fix this test to work with NFT mode.")
		}
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = api.IPIPModeNever
		options.DelayFelixStart = true
		options.FelixLogSeverity = "Debug"
		tc, client = infrastructure.StartNNodeTopology(2, options, infra)

		infra.AddDefaultAllow()

		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInInfra(infra)

			hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
		}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")
			}
		}

		for _, wl := range w {
			wl.Stop()
		}
		for _, wl := range hostW {
			wl.Stop()
		}
		tc.Stop()

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	entry := func(chainPolicy string, epToHostPol string, hep string, hepPolicy api.Action, expectedConn connectivity.Expected) table.TableEntry {
		return table.Entry(
			fmt.Sprintf("INPUT=%s, ep-to-host=%s, HEP=%s, HEP-pol=%s, expected connectivity=%v",
				chainPolicy, epToHostPol, hep, hepPolicy, expectedConn),
			chainPolicy, epToHostPol, hep, hepPolicy, expectedConn,
		)
	}

	table.DescribeTable("endpoint to host tests",
		func(chainPolicy string, epToHostPol string, hepIface string, hepPolicy api.Action, expectedConn connectivity.Expected) {
			// Set the chain policy.
			for _, f := range tc.Felixes {
				// Need to make sure Felix's datastore connection is allowed to return.
				f.Exec("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
				// Make sure there's no WEP-to-WEP connectivity before Felix comes up.
				f.Exec("iptables", "-t", "filter", "-P", "FORWARD", "DROP")
				f.Exec("iptables", "-t", "filter", "-P", "INPUT", chainPolicy)
			}
			// Set Felix policy.
			By("Updating DefaultEndpointToHostAction")
			utils.UpdateFelixConfig(client, func(configuration *api.FelixConfiguration) {
				configuration.Spec.DefaultEndpointToHostAction = epToHostPol
			})

			switch hepIface {
			case "none":
			case "eth0", "*", "*-pre-dnat":
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "default-hep-egress"
				policy.Spec.Selector = "hep=='true'"
				policy.Spec.Egress = []api.Rule{
					{
						Action: api.Allow,
					},
				}
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				policy = api.NewGlobalNetworkPolicy()
				policy.Name = "default-hep"
				policy.Spec.Selector = "hep=='true'"

				if hepIface == "*-pre-dnat" {
					policy.Spec.ApplyOnForward = true
					policy.Spec.PreDNAT = true
					hepIface = "*"

					// pre-DNAT applies to forwarded traffic, need to allow workload traffic explicitly.
					policy.Spec.Ingress = append(policy.Spec.Ingress, api.Rule{
						Action: api.Allow,
						Source: api.EntityRule{
							Selector: "!has(hep)",
						},
						Destination: api.EntityRule{
							Selector: "!has(hep)",
						},
					})
				}

				policy.Spec.Ingress = append(policy.Spec.Ingress, api.Rule{
					Action: hepPolicy,
					Source: api.EntityRule{
						Selector: "!has(hep)",
					},
				})

				_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				for _, f := range tc.Felixes {
					hep := api.NewHostEndpoint()
					hep.Name = "hep-" + f.Name
					hep.Labels = map[string]string{
						"hep": "true",
					}
					hep.Spec.Node = f.Hostname
					hep.Spec.ExpectedIPs = []string{f.IP}
					hep.Spec.InterfaceName = hepIface
					_, err := client.HostEndpoints().Create(context.TODO(), hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
				}
			default:
				Fail("Unknown hep type: " + hepIface)
			}

			// Check that we start with no WEP-to-WEP connectivity.  This ensures that, when
			// we see WEP-to-WEP connectivity in the check below, we know that Felix has
			// finished programming the dataplane.
			cc.Expect(connectivity.None, w[0], w[1])
			cc.CheckConnectivity()
			cc.ResetExpectations()

			// Trigger startup, Felix will apply the ep-to-host policy and the WEP-to-WEP
			// allow profile in one transaction.
			for _, f := range tc.Felixes {
				f.TriggerDelayedStart()
			}

			// Now add the default allow profile, which should give us WEP-to-WEP connectivity.
			// When we get WEp-to-WEP, we know that Felix has finished programming so the
			// WEP-to-host test is valid.

			By("Checking connectivity")
			cc.Expect(expectedConn, w[0], hostW[0])
			cc.Expect(expectedConn, w[1], hostW[1])
			cc.Expect(connectivity.Some, w[0], w[1])
			cc.CheckConnectivity()
		},
		entry("DROP", "Accept", "none", "", connectivity.Some),
		entry("DROP", "Return", "none", "", connectivity.None),
		entry("DROP", "Drop", "none", "", connectivity.None),

		entry("ACCEPT", "Accept", "none", "", connectivity.Some),
		entry("ACCEPT", "Return", "none", "", connectivity.Some),
		entry("ACCEPT", "Drop", "none", "", connectivity.None),

		// HEP on eth0 is irrelevant: an interface-specific HEP has no effect on workload traffic.
		entry("ACCEPT", "Return", "eth0", api.Deny, connectivity.Some),
		entry("DROP", "Return", "eth0", api.Deny, connectivity.None),

		// Pre-dnat policy is applied before normal policy and before the DefaultEndpointToHostAction
		// so it can drop extra traffic.  However, it can't allow traffic that DefaultEndpointToHostAction
		// would then drop, because both checks are enforced.
		entry("DROP", "Accept", "*-pre-dnat", api.Allow, connectivity.Some),
		entry("DROP", "Return", "*-pre-dnat", api.Allow, connectivity.None),
		entry("DROP", "Drop", "*-pre-dnat", api.Allow, connectivity.None),

		entry("DROP", "Accept", "*-pre-dnat", api.Deny, connectivity.None),
		entry("DROP", "Return", "*-pre-dnat", api.Deny, connectivity.None),
		entry("DROP", "Drop", "*-pre-dnat", api.Deny, connectivity.None),

		entry("ACCEPT", "Accept", "*-pre-dnat", api.Deny, connectivity.None),
		entry("ACCEPT", "Return", "*-pre-dnat", api.Deny, connectivity.None),
		entry("ACCEPT", "Drop", "*-pre-dnat", api.Deny, connectivity.None),

		// DefaultEndpointToHostAction overrides normal wildcard HEP policy (this
		// surprised me, but I think it was a change made near the end of development to prevent
		// a breaking change).
		entry("DROP", "Accept", "*", api.Allow, connectivity.Some),
		entry("DROP", "Return", "*", api.Allow, connectivity.None),
		entry("DROP", "Drop", "*", api.Allow, connectivity.None),

		entry("DROP", "Accept", "*", api.Deny, connectivity.Some),
		entry("DROP", "Return", "*", api.Deny, connectivity.None),
		entry("DROP", "Drop", "*", api.Deny, connectivity.None),

		entry("ACCEPT", "Accept", "*", api.Deny, connectivity.Some),
		entry("ACCEPT", "Return", "*", api.Deny, connectivity.Some),
		entry("ACCEPT", "Drop", "*", api.Deny, connectivity.None),
	)
})
