// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ qos policy tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra          infrastructure.DatastoreInfra
		tc             infrastructure.TopologyContainers
		w              [3]*workload.Workload
		client         client.Interface
		externalClient *containers.Container
		cc             *connectivity.Checker
	)

	BeforeEach(func() {
		iOpts := []infrastructure.CreateOption{}
		infra = getInfra(iOpts...)
		if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
			Skip("Skipping NFT / BPF test for etcdv3 backend.")
		}

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = apiv3.IPIPModeNever
		options.FelixLogSeverity = "Debug"
		tc, client = infrastructure.StartNNodeTopology(3, options, infra)

		w, _ = setupIPIPWorkloads(infra, tc, options, client)
		cc = &connectivity.Checker{}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		externalClient = infrastructure.RunExtClient("ext-client")
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				if NFTMode() {
					logNFTDiags(felix)
				} else {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip6tables-save", "-c")
				}
				felix.Exec("ip", "r")
				felix.Exec("calico-bpf", "policy", "dump", "eth0", "all", "--asm")
				felix.Exec("calico-bpf", "-6", "policy", "dump", "eth0", "all", "--asm")
				felix.Exec("calico-bpf", "counters", "dump")
			}
		}

		for _, wl := range w {
			wl.Stop()
		}
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
		externalClient.Stop()
	})

	It("pepper0 should have expected restriction on the nat outgoing rule", func() {
		if NFTMode() {
			// TODO (mazdak) verify the pattern
			// TODO (mazdak): add ipv6
			pattern := "ip saddr @cali40all-ipam-pools ip daddr != @cali40all-ipam-pools .* jump mangle-cali-qos-policy"
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "mangle-cali-POSTROUTING")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(pattern))
		} else {
			expectedRule := "-m set --match-set cali40all-ipam-pools src -m set ! --match-set cali40all-ipam-pools dst -j cali-qos-policy"
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "mangle")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedRule))
		}
	})

	It("pepper1 applying QoSControl should is adding correct rules", func() {
		By("configurging external client to only accept packets with sepcific DSCP value")
		externalClient.Exec("ip", "route", "add", w[0].IP, "via", tc.Felixes[0].IP)
		externalClient.Exec("ip", "route", "add", w[1].IP, "via", tc.Felixes[1].IP)
		externalClient.Exec("iptables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x14", "-j", "DROP")

		cc.ResetExpectations()
		cc.ExpectNone(externalClient, w[0])
		cc.ExpectNone(externalClient, w[1])
		cc.CheckConnectivity()

		By("setting the expected DSCP value on egress traffic from one workload leaving the cluster")
		w[0].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: numorstring.DSCPFromInt(20),
		}
		w[0].UpdateInInfra(infra)
		//time.Sleep(time.Minute * 540)
		cc.ResetExpectations()
		cc.ExpectSome(externalClient, w[0])
		cc.ExpectNone(externalClient, w[1])
		cc.CheckConnectivity()

		By("verifying that expected rule exists")
		if NFTMode() {
			// TODO (mazdak) verify the pattern
			// TODO (mazdak): add ipv6
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "mangle-cali-qos-policy")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("ip dscp set af22"))
			Consistently(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "mangle-cali-qos-policy")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("ip dscp set af22"))
		} else {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "mangle")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("DSCP --set-dscp 0x14"))
			Consistently(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "mangle")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("DSCP --set-dscp 0x14"))
		}

		By("resetting DSCP value on egress traffic from that workload leaving the cluster")
		w[0].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		w[0].UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectNone(externalClient, w[0])
		cc.ExpectNone(externalClient, w[1])
		cc.CheckConnectivity()

		By("verifying that expected rule is cleaned up")
		if NFTMode() {
			// TODO (mazdak) verify the pattern
			// TODO (mazdak): add ipv6
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "mangle-cali-qos-policy")
				return output
			}, 5*time.Second, 100*time.Millisecond).ShouldNot(ContainSubstring("ip dscp set af22"))
			Consistently(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "mangle-cali-qos-policy")
				return output
			}, 5*time.Second, 100*time.Millisecond).ShouldNot(ContainSubstring("ip dscp set af22"))
		} else {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "mangle")
				return output
			}, 5*time.Second, 100*time.Millisecond).ShouldNot(ContainSubstring("DSCP --set-dscp 0x14"))
			Consistently(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "mangle")
				return output
			}, 5*time.Second, 100*time.Millisecond).ShouldNot(ContainSubstring("DSCP --set-dscp 0x14"))
		}
	})
})
