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

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"

	. "github.com/onsi/ginkgo"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ iptables cleanup tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra   infrastructure.DatastoreInfra
		felix   *infrastructure.Felix
		options infrastructure.TopologyOptions
	)

	BeforeEach(func() {
		infra = getInfra()
		options = infrastructure.DefaultTopologyOptions()
		options.ExtraEnvVars["FELIX_IptablesRefreshInterval"] = "1" // Make sure Felix re-scans iptables frequently
		felix, _ = infrastructure.StartSingleNodeTopology(options, infra)
	})

	Describe("with a range of rules in iptables", func() {
		BeforeEach(func() {
			err := felix.CopyFileIntoContainer("iptables-dump.txt", "/iptables-dump.txt")
			Expect(err).ToNot(HaveOccurred(), "Failed to copy iptables dump into felix container")
			Eventually(func() error {
				// Can fail if felix is trying to do a concurrent update.  Just keep trying...
				return felix.ExecMayFail("iptables-restore", "/iptables-dump.txt")
			}, "5s", "100ms").ShouldNot(HaveOccurred())
		})

		const kubeChainsThatShouldBeCleanedUp = `KUBE-(SERVICES|EXTERNAL-SERVICES|NODEPORTS|FORWARD|SVC|SEP|FW|XLB)`
		const kubeChainsThatShouldNeverBeCleanedUp = `KUBE-(MARK-MASQ|MARK-DROP|KUBE-FIREWALL)`
		const caliChainsThatShouldBeCleanedUp = `cali-old-chain`

		dumpIptables := func() string {
			out, err := felix.ExecOutput("iptables-save")
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
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
		}
	})

	AfterEach(func() {
		log.Info("AfterEach starting")
		felix.Exec("calico-bpf", "connect-time", "clean")
		felix.Stop()
		infra.Stop()
		log.Info("AfterEach done")
	})
})
