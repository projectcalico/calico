// +build fvtests

// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("VXLAN topology before adding host IPs to IP sets", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
		w       [3]*workload.Workload
		hostW   [3]*workload.Workload
		cc      *workload.ConnectivityChecker
	)

	BeforeEach(func() {
		infra = getInfra()
		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.VXLANEnabled = true
		topologyOptions.IPIPEnabled = false
		felixes, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Wait until the vxlan device appears.
		Eventually(func() error {
			for i, f := range felixes {
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
		}, "10s", "100ms").ShouldNot(HaveOccurred())

		// Create workloads, using that profile.  One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(wIP),
				HandleID: &wName,
				Attrs: map[string]string{
					ipam.AttributeNode: felixes[ii].Hostname,
				},
				Hostname: felixes[ii].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInDatastore(infra)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
		}

		cc = &workload.ConnectivityChecker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
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
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	It("should use the --random-fully flag in the MASQUERADE rules", func() {
		for _, felix := range felixes {
			Eventually(func() string {
				out, _ := felix.ExecOutput("iptables-save", "-c")
				return out
			}, "10s", "100ms").Should(ContainSubstring("--random-fully"))
		}
	})

	It("should have workload to workload connectivity", func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.CheckConnectivity()
	})

	It("should have host to workload connectivity", func() {
		cc.ExpectSome(felixes[0], w[1])
		cc.ExpectSome(felixes[0], w[0])
		cc.CheckConnectivity()
	})

	It("should have host to host connectivity", func() {
		cc.ExpectSome(felixes[0], hostW[1])
		cc.ExpectSome(felixes[1], hostW[0])
		cc.CheckConnectivity()
	})

	Context("with host protection policy in place", func() {
		BeforeEach(func() {
			// Make sure our new host endpoints don't cut felix off from the datastore.
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "eth0-" + f.Name
				hep.Labels = map[string]string{
					"host-endpoint": "true",
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should have workload connectivity but not host connectivity", func() {
			// Host endpoints (with no policies) block host-host traffic due to default drop.
			cc.ExpectNone(felixes[0], hostW[1])
			cc.ExpectNone(felixes[1], hostW[0])
			// But the rules to allow VXLAN between our hosts let the workload traffic through.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	Context("with all-interfaces host protection policy in place", func() {
		BeforeEach(func() {
			// Make sure our new host endpoints don't cut felix off from the datastore.
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "all-interfaces-" + f.Name
				hep.Labels = map[string]string{
					"host-endpoint": "true",
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				hep.Spec.InterfaceName = "*"
				_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "allow-all-prednat"
			order := float64(20)
			policy.Spec.Order = &order
			policy.Spec.PreDNAT = true
			policy.Spec.ApplyOnForward = true
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = "has(host-endpoint)"
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should not block any traffic", func() {
			// An all-interfaces host endpoint does not block any traffic by default.
			cc.ExpectSome(felixes[0], hostW[1])
			cc.ExpectSome(felixes[1], hostW[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	Context("after removing BGP address from third node", func() {
		// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
		BeforeEach(func() {
			Eventually(func() int {
				return getNumIPSetMembers(felixes[0].Container, "cali40all-vxlan-net")
			}, "5s", "200ms").Should(Equal(len(felixes) - 1))

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			node, err := client.Nodes().Get(ctx, felixes[2].Hostname, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Pause felix so it can't touch the dataplane!
			pid := felixes[2].GetFelixPID()
			felixes[2].Exec("kill", "-STOP", fmt.Sprint(pid))

			node.Spec.BGP = nil
			_, err = client.Nodes().Update(ctx, node, options.SetOptions{})
		})

		It("should have no connectivity from third felix and expected number of IPs in whitelist", func() {
			Eventually(func() int {
				return getNumIPSetMembers(felixes[0].Container, "cali40all-vxlan-net")
			}, "5s", "200ms").Should(Equal(len(felixes) - 2))

			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectNone(w[0], w[2])
			cc.ExpectNone(w[1], w[2])
			cc.ExpectNone(w[2], w[0])
			cc.ExpectNone(w[2], w[1])
			cc.CheckConnectivity()
		})
	})

	// Explicitly verify that the VXLAN whitelist IP set is doing its job (since Felix makes multiple dataplane
	// changes when the BGP IP disappears and we want to make sure that its the whitelist that's causing the
	// connectivity to drop).
	Context("after removing BGP address from third node, all felixes paused", func() {
		// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
		BeforeEach(func() {
			// Check we initially have the expected number of whitelist entries.
			for _, f := range felixes {
				// Wait for Felix to set up the whitelist.
				Eventually(func() int {
					return getNumIPSetMembers(f.Container, "cali40all-vxlan-net")
				}, "5s", "200ms").Should(Equal(len(felixes) - 1))
			}

			// Wait until dataplane has settled.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.ExpectSome(w[1], w[2])
			cc.CheckConnectivity()
			cc.ResetExpectations()

			// Then pause all the felixes.
			for _, f := range felixes {
				pid := f.GetFelixPID()
				f.Exec("kill", "-STOP", fmt.Sprint(pid))
			}
		})

		It("after manually removing third node from whitelist should have expected connectivity", func() {
			felixes[0].Exec("ipset", "del", "cali40all-vxlan-net", felixes[2].IP)

			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[1], w[2])
			cc.ExpectNone(w[2], w[0])
			cc.CheckConnectivity()
		})
	})

	It("should configure the vxlan device correctly", func() {
		// The VXLAN device should appear with default MTU, etc.
		for _, felix := range felixes {
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("mtu 1410"))
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("vxlan id 4096"))
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("dstport 4789"))
		}

		// Change the MTU.
		felixConfig, err := client.FelixConfigurations().Get(context.Background(), "default", options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		mtu := 1400
		vni := 4097
		port := 4790
		felixConfig.Spec.VXLANMTU = &mtu
		felixConfig.Spec.VXLANPort = &port
		felixConfig.Spec.VXLANVNI = &vni
		_, err = client.FelixConfigurations().Update(context.Background(), felixConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Expect the settings to be changed on the device.
		for _, felix := range felixes {
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("mtu 1400"))
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("vxlan id 4097"))
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("dstport 4790"))
		}
	})

	It("should delete the vxlan device when vxlan is disabled", func() {
		// Wait for the VXLAN device to be created.
		for _, felix := range felixes {
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").Should(ContainSubstring("mtu 1410"))
		}

		// Disable VXLAN in Felix.
		felixConfig, err := client.FelixConfigurations().Get(context.Background(), "default", options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		enabled := false
		felixConfig.Spec.VXLANEnabled = &enabled
		_, err = client.FelixConfigurations().Update(context.Background(), felixConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Expect the VXLAN device to be deleted.
		for _, felix := range felixes {
			Eventually(func() string {
				out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
				return out
			}, "10s", "100ms").ShouldNot(ContainSubstring("mtu 1410"))
		}
	})

})
