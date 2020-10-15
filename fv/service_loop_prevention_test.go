// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// +build fvtests

package fv_test

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
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
		if CurrentGinkgoTestDescription().Failed {
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
		if CurrentGinkgoTestDescription().Failed {
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

	It("programs iptables as expected to block service routing loops", func() {

		By("configuring service cluster IPs")
		updateBGPConfig(func(cfg *api.BGPConfiguration) {
			cfg.Spec.ServiceClusterIPs = []api.ServiceClusterIPBlock{
				{
					CIDR: "1.2.0.0/16",
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
				MatchRegexp("-A cali-cidr-block -d 1\\.2\\.0\\.0/16 .* -j DROP"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save")).Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d fd5f::/119 .* -j DROP"),
			))
		}

		By("configuring ServiceLoopPrevention=Reject")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Reject"
		})

		// Expect to see rules in cali-cidr-block chains with REJECT.  (Allowing time for a
		// Felix restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "4s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d 1\\.2\\.0\\.0/16 .* -j REJECT"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save"), "4s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d fd5f::/119 .* -j REJECT"),
			))
		}

		By("configuring ServiceLoopPrevention=Disabled")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Disabled"
		})

		// Expect to see empty cali-cidr-block chains.  (Allowing time for a Felix restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "4s", "0.5s").Should(BeEmpty())
			Eventually(getCIDRBlockRules(felix, "ip6tables-save"), "4s", "0.5s").Should(BeEmpty())
		}

		By("configuring ServiceLoopPrevention=Drop")
		updateFelixConfig(func(cfg *api.FelixConfiguration) {
			cfg.Spec.ServiceLoopPrevention = "Drop"
		})

		// Expect to see rules in cali-cidr-block chains with DROP.  (Allowing time for a
		// Felix restart.)
		for _, felix := range felixes {
			Eventually(getCIDRBlockRules(felix, "iptables-save"), "4s", "0.5s").Should(ConsistOf(
				MatchRegexp("-A cali-cidr-block -d 1\\.2\\.0\\.0/16 .* -j DROP"),
			))
			Eventually(getCIDRBlockRules(felix, "ip6tables-save"), "4s", "0.5s").Should(ConsistOf(
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
	})
})
