//go:build fvtests

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
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ iptables cleanup tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		tc      infrastructure.TopologyContainers
		options infrastructure.TopologyOptions
	)

	BeforeEach(func() {
		infra = getInfra()
		options = infrastructure.DefaultTopologyOptions()
		options.ExtraEnvVars["FELIX_IptablesRefreshInterval"] = "1" // Make sure Felix re-scans iptables frequently
		tc, _ = infrastructure.StartSingleNodeTopology(options, infra)
	})

	Describe("with a range of rules in iptables", func() {
		BeforeEach(func() {
			if NFTMode() {
				Skip("This test is not yet supported in nftables mode")
			}
			err := tc.Felixes[0].CopyFileIntoContainer("iptables-dump.txt", "/iptables-dump.txt")
			Expect(err).ToNot(HaveOccurred(), "Failed to copy iptables dump into felix container")
			Eventually(func() error {
				// Can fail if felix is trying to do a concurrent update.  Just keep trying...
				return tc.Felixes[0].ExecMayFail("iptables-restore", "/iptables-dump.txt")
			}, "5s", "100ms").ShouldNot(HaveOccurred())
		})

		const kubeChainsThatShouldBeCleanedUp = `KUBE-(SERVICES|EXTERNAL-SERVICES|NODEPORTS|FORWARD|SVC|SEP|FW|XLB)`
		const kubeChainsThatShouldNeverBeCleanedUp = `KUBE-(MARK-MASQ|MARK-DROP|KUBE-FIREWALL)`
		const caliChainsThatShouldBeCleanedUp = `cali-old-chain`

		dumpIptables := func() string {
			out, err := tc.Felixes[0].ExecOutput("iptables-save")
			Expect(err).NotTo(HaveOccurred())
			return out
		}

		if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
			It("_BPF_ should clean up kube-proxy's rules", func() {
				Eventually(dumpIptables, "5s").ShouldNot(MatchRegexp(kubeChainsThatShouldBeCleanedUp))
				Consistently(dumpIptables, "2s").Should(MatchRegexp(kubeChainsThatShouldNeverBeCleanedUp))
			})
		} else {
			It("should leave kube-proxy rules alone", func() {
				Consistently(dumpIptables, "5s").Should(MatchRegexp(kubeChainsThatShouldBeCleanedUp))
			})
		}
		It("should clean up our rules", func() {
			Eventually(dumpIptables, "5s").ShouldNot(MatchRegexp(caliChainsThatShouldBeCleanedUp))
		})
	})

	JustAfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			tc.Felixes[0].Exec("iptables-save", "-c")
			tc.Felixes[0].Exec("ip", "r")
		}
	})

	AfterEach(func() {
		log.Info("AfterEach starting")
		tc.Felixes[0].Exec("calico-bpf", "connect-time", "clean")
		tc.Stop()
		infra.Stop()
		log.Info("AfterEach done")
	})
})
