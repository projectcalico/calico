// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("service loop prevention; with 2 nodes", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
	)

	BeforeEach(func() {
		infra = getInfra()

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPEnabled = false
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")
			}
		}
		for _, felix := range felixes {
			felix.Stop()
		}
		if CurrentSpecReport().Failed() {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	updateFelixConfig := func(deltaFn func(*api.FelixConfiguration)) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
		if _, doesNotExist := err.(errors.ErrorResourceDoesNotExist); doesNotExist {
			cfg = api.NewFelixConfiguration()
			cfg.Name = "default"
			deltaFn(cfg)
			_, err = client.FelixConfigurations().Create(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			deltaFn(cfg)
			_, err = client.FelixConfigurations().Update(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
	}

	updateBGPConfig := func(deltaFn func(*api.BGPConfiguration)) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg, err := client.BGPConfigurations().Get(ctx, "default", options.GetOptions{})
		if _, doesNotExist := err.(errors.ErrorResourceDoesNotExist); doesNotExist {
			cfg = api.NewBGPConfiguration()
			cfg.Name = "default"
			deltaFn(cfg)
			_, err = client.BGPConfigurations().Create(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			deltaFn(cfg)
			_, err = client.BGPConfigurations().Update(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
	}

	getCIDRBlockRules := func(felix *infrastructure.Felix, saveCommand string) func() []string {
		return func() []string {
			out, err := felix.ExecOutput(saveCommand, "-t", "filter")
			Expect(err).NotTo(HaveOccurred())
			var cidrBlockLines []string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "-A cali-cidr-block") {
					cidrBlockLines = append(cidrBlockLines, line)
				}
			}
			return cidrBlockLines
		}
	}

	tryRoutingLoop := func(expectLoop bool) {

		// Run containers to model a default gateway, and an external client connecting to
		// services within the cluster via that gateway.
		externalGW := containers.Run("external-gw",
			containers.RunOpts{AutoRemove: true},
			"--privileged", // So that we can add routes inside the container.
			utils.Config.BusyboxImage,
			"/bin/sh", "-c", "sleep 1000")
		defer externalGW.Stop()

		externalClient := containers.Run("external-client",
			containers.RunOpts{AutoRemove: true},
			"--privileged", // So that we can add routes inside the container.
			utils.Config.BusyboxImage,
			"/bin/sh", "-c", "sleep 1000")
		defer externalClient.Stop()

		// Add a service CIDR route in those containers, similar to the routes that they
		// would have via BGP per our service advertisement feature.  (This should really be
		// an ECMP route to both Felixes, but busybox's ip can't program ECMP routes, and a
		// non-ECMP route is sufficient to demonstrate the looping issue.)
		externalClient.Exec("ip", "r", "a", "10.96.0.0/17", "via", externalGW.IP)
		externalGW.Exec("ip", "r", "a", "10.96.0.0/17", "via", felixes[0].IP)

		// Configure the external gateway client to forward, in order to create the
		// conditions for looping.
		externalClient.Exec("sysctl", "-w", "net.ipv4.ip_forward=1")
		externalGW.Exec("sysctl", "-w", "net.ipv4.ip_forward=1")

		// Also tell Felix to route that CIDR to the external gateway.
		felixes[0].ExecMayFail("ip", "r", "d", "10.96.0.0/17")
		felixes[0].Exec("ip", "r", "a", "10.96.0.0/17", "via", externalGW.IP)
		felixes[0].Exec("iptables", "-P", "FORWARD", "ACCEPT")

		// Start monitoring all packets, on the Felix, to or from a specific (but
		// unused) service IP.
		tcpdumpF := felixes[0].AttachTCPDump("eth0")
		tcpdumpF.AddMatcher("serviceIPPackets", regexp.MustCompile("10\\.96\\.0\\.19"))
		tcpdumpF.Start()
		defer tcpdumpF.Stop()

		// Send a single ping from the external client to the unused service IP.
		err := externalClient.ExecMayFail("ping", "-c", "1", "-W", "1", "10.96.0.19")
		Expect(err).To(HaveOccurred())

		countServiceIPPackets := func() int {
			// Return the number of packets observed to/from 10.96.0.19.
			return tcpdumpF.MatchCount("serviceIPPackets")
		}

		if expectLoop {
			// Tcpdump should see more than 2 packets, because of looping.  Note: 2
			// packets would be Felix receiving the ping and then forwarding it out
			// again.  I want to check here that it's also looped around again by the
			// gateway, resulting in MORE THAN 2 packets.
			Eventually(countServiceIPPackets).Should(BeNumerically(">", 2))
		} else {
			// Tcpdump should see just 1 packet, the request, with no response (because
			// we DROP) and no looping.
			Eventually(countServiceIPPackets).Should(BeNumerically("==", 1))
		}
	}

	It("programs iptables as expected to block service routing loops", func() {

		By("configuring service cluster IPs")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceClusterIPs = []api.ServiceClusterIPBlock{
				{
					CIDR: "10.96.0.0/17",
				},
				{
					CIDR: "fd5f::/119",
				},
			}
		})

		// Default ServiceLoopPrevention is Drop, so expect to see rules in cali-cidr-block
		// chains with DROP.  (Felix handles BGPConfiguration without restarting, so this
		// should be quick.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save")).Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d 10\\.96\\.0\\.0/17 .* -j DROP"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save")).Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d fd5f::/119 .* -j DROP"),
			))
		}

		By("test that we don't get a routing loop")
		tryRoutingLoop(false)

		By("configuring ServiceLoopPrevention=Reject")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Reject"
		})

		// Expect to see rules in cali-cidr-block chains with REJECT.  (Allowing time for a
		// Felix restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "8s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d 10\\.96\\.0\\.0/17 .* -j REJECT"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save"), "8s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d fd5f::/119 .* -j REJECT"),
			))
		}

		By("configuring ServiceLoopPrevention=Disabled")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Disabled"
		})

		// Expect to see empty cali-cidr-block chains.  (Allowing time for a Felix restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "8s", "0.5s").Should(BeEmpty())
			Eventually(getCIDRBlockRules(felix, "ip6tables-save"), "8s", "0.5s").Should(BeEmpty())
		}

		By("test that we DO get a routing loop")
		// (In order to test that the tryRoutingLoop setup is genuine.)
		tryRoutingLoop(true)

		By("configuring ServiceLoopPrevention=Drop")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Drop"
		})

		// Expect to see rules in cali-cidr-block chains with DROP.  (Allowing time for a
		// Felix restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "8s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d 10\\.96\\.0\\.0/17 .* -j DROP"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save"), "8s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d fd5f::/119 .* -j DROP"),
			))
		}

		By("updating the service CIDRs")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceClusterIPs = []api.ServiceClusterIPBlock{
				{
					CIDR: "1.1.0.0/16",
				},
				{
					CIDR: "fd5e::/119",
				},
			}
		})

		// Expect to see rules in cali-cidr-block chains with DROP and the updated CIDRs.
		// (BGPConfiguration change is handled without needing a restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save")).Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d 1\\.1\\.0\\.0/16 .* -j DROP"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save")).Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d fd5e::/119 .* -j DROP"),
			))
		}

		By("resetting BGP config")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceClusterIPs = nil
		})
	})

	It("ServiceExternalIPs also blocks service routing loop", func() {
		By("configuring service external IPs")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceExternalIPs = []api.ServiceExternalIPBlock{
				{
					CIDR: "10.96.0.0/17",
				},
			}
		})

		By("test that we don't get a routing loop")
		tryRoutingLoop(false)

		By("configuring ServiceLoopPrevention=Disabled")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Disabled"
		})

		// Expect to see empty cali-cidr-block chains.  (Allowing time for a Felix
		// restart.)  This ensures that the cali-cidr-block chain has been cleared
		// before we try a test ping.
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "8s", "0.5s").Should(BeEmpty())
		}

		By("test that we DO get a routing loop")
		// (In order to test that the tryRoutingLoop setup is genuine.)
		tryRoutingLoop(true)

		By("resetting BGP config")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceExternalIPs = nil
		})
	})

	It("ServiceLoadBalancerIPs also blocks service routing loop", func() {
		By("configuring service LB IPs")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceLoadBalancerIPs = []api.ServiceLoadBalancerIPBlock{
				{
					CIDR: "10.96.0.0/17",
				},
			}
		})

		By("test that we don't get a routing loop")
		tryRoutingLoop(false)

		By("configuring ServiceLoopPrevention=Disabled")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Disabled"
		})

		// Expect to see empty cali-cidr-block chains.  (Allowing time for a Felix
		// restart.)  This ensures that the cali-cidr-block chain has been cleared
		// before we try a test ping.
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "8s", "0.5s").Should(BeEmpty())
		}

		By("test that we DO get a routing loop")
		// (In order to test that the tryRoutingLoop setup is genuine.)
		tryRoutingLoop(true)

		By("resetting BGP config")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceLoadBalancerIPs = nil
		})
	})

})
