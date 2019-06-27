// +build fvtests

// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("IPIP topology before adding host IPs to IP sets", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
		w       [2]*workload.Workload
		hostW   [2]*workload.Workload
		cc      *workload.ConnectivityChecker
	)

	BeforeEach(func() {
		infra = getInfra()
		felixes, client = infrastructure.StartNNodeTopology(2, infrastructure.DefaultTopologyOptions(), infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Wait until the tunl0 device appears; it is created when felix inserts the ipip module
		// into the kernel.
		Eventually(func() error {
			links, err := netlink.LinkList()
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Attrs().Name == "tunl0" {
					return nil
				}
			}
			return errors.New("tunl0 wasn't auto-created")
		}).Should(BeNil())

		// Create workloads, using that profile.  One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
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
			// But the rules to allow IPIP between our hosts let the workload traffic through.
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

	Context("after removing BGP address from nodes", func() {
		// Simulate having a host send IPIP traffic from an unknown source, should get blocked.
		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			l, err := client.Nodes().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, node := range l.Items {
				node.Spec.BGP = nil
				_, err := client.Nodes().Update(ctx, &node, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			// Removing the BGP config triggers a Felix restart and Felix has a 2s timer during
			// a config restart to ensure that it doesn't tight loop.  Wait for the ipset to be
			// updated as a signal that Felix has restarted.
			for _, f := range felixes {
				Eventually(func() int {
					return getNumIPSetMembers(f.Container, "cali40all-hosts-net")
				}, "5s", "200ms").Should(BeZero())
			}
		})

		It("should have no workload to workload connectivity", func() {
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	Context("external nodes configured", func() {
		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			l, err := client.Nodes().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			// Now remove the BGP configuration for felixes[0]
			var prevBGPSpec api.NodeBGPSpec
			for _, node := range l.Items {
				log.Infof("node: %v", node)
				if node.Name == felixes[0].Name {
					// save the old spec
					prevBGPSpec = *node.Spec.BGP
					node.Spec.BGP = nil
					_, err = client.Nodes().Update(ctx, &node, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
				}
			}
			// Removing the BGP config triggers a Felix restart. Wait for the ipset to be updated as a signal that Felix
			// has restarted.
			for _, f := range felixes {
				Eventually(func() int {
					return getNumIPSetMembers(f.Container, "cali40all-hosts-net")
				}, "5s", "200ms").Should(Equal(1))
			}

			updateConfig := func(addr string) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				c, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				c.Spec.ExternalNodesCIDRList = &[]string{addr, "1.1.1.1"}
				log.WithFields(log.Fields{"felixconfiguration": c, "adding Addr": addr}).Info("Updating FelixConfiguration ")
				_, err = client.FelixConfigurations().Update(ctx, c, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
			updateConfig(prevBGPSpec.IPv4Address)
			// Wait for the config to take
			for _, f := range felixes {
				Eventually(func() int {
					return getNumIPSetMembers(f.Container, "cali40all-hosts-net")
				}, "5s", "200ms").Should(Equal(3))
			}
		})

		It("should have all-hosts-net ipset configured with the external hosts and workloads connect", func() {
			f := felixes[0]
			// Add the ip route via tunnel back on the Felix for which we nuked when we removed its BGP spec.
			f.Exec("ip", "route", "add", w[1].IP, "via", felixes[1].IP, "dev", "tunl0", "onlink")
			cc.ExpectSome(w[0], w[1])
			cc.CheckConnectivity()
		})
	})
})

func getNumIPSetMembers(c *containers.Container, ipSetName string) int {
	ipsetsOutput, err := c.ExecOutput("ipset", "list")
	Expect(err).NotTo(HaveOccurred())
	numMembers := map[string]int{}
	currentName := ""
	membersSeen := false
	log.WithField("ipsets", ipsetsOutput).Info("IP sets state")
	for _, line := range strings.Split(ipsetsOutput, "\n") {
		log.WithField("line", line).Debug("Parsing line")
		if strings.HasPrefix(line, "Name:") {
			currentName = strings.Split(line, " ")[1]
			membersSeen = false
		} else if strings.HasPrefix(line, "Members:") {
			membersSeen = true
		} else if membersSeen && len(strings.TrimSpace(line)) > 0 {
			log.Debugf("IP set %s has member %s", currentName, line)
			numMembers[currentName]++
		}
	}
	return numMembers[ipSetName]
}
