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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ qos policy tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPortStr = "8055"
	)

	var (
		infra        infrastructure.DatastoreInfra
		tc           infrastructure.TopologyContainers
		ep1_1, ep2_1 *workload.Workload // Workloads on Felix0
		ep1_2        *workload.Workload // Workloads on Felix1
		extClient    *containers.Container
		cc           *connectivity.Checker

		toExists    bool = true
		toNotExists bool = false
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
		tc, _ = infrastructure.StartNNodeTopology(2, options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1 (Felix0).
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		ep2_1 = workload.Run(tc.Felixes[0], "ep2-1", "default", "10.65.1.0", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		// Create workload on host 2 (Felix1)
		ep1_2 = workload.Run(tc.Felixes[1], "ep1-2", "default", "10.65.1.1", wepPortStr, "tcp")
		ep1_2.ConfigureInInfra(infra)

		cc = &connectivity.Checker{}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		extClientOpts := infrastructure.ExtClientOpts{
			Image: utils.Config.FelixImage,
		}
		extClient = infrastructure.RunExtClientWithOpts("ext-client1", extClientOpts)
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

		ep1_1.Stop()
		ep2_1.Stop()
		ep1_2.Stop()
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
		extClient.Stop()
	})

	It("pepper0 should have expected restriction on the nat outgoing rule", func() {
		if NFTMode() {
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

	It("pepper1 applying DSCP annotation should result is adding correct rules", func() {
		dscp20 := numorstring.DSCPFromInt(20) // 0x14
		dscp32 := numorstring.DSCPFromInt(32) // 0x20
		dscp40 := numorstring.DSCPFromInt(40) // 0x28
		dscp0 := numorstring.DSCPFromInt(0)   // 0x0

		By("configurging external client to only accept packets with specific DSCP value")
		extClient.Exec("ip", "route", "add", ep1_1.IP, "via", tc.Felixes[0].IP)
		extClient.Exec("ip", "route", "add", ep2_1.IP, "via", tc.Felixes[0].IP)
		extClient.Exec("ip", "route", "add", ep1_2.IP, "via", tc.Felixes[1].IP)
		extClient.Exec("iptables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x14", "-j", "DROP")

		cc.ResetExpectations()
		cc.ExpectNone(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectNone(extClient, ep1_2)
		cc.CheckConnectivity()

		expectNoQosPolicy(tc.Felixes[0])
		expectNoQosPolicy(tc.Felixes[1])

		By("setting the expected DSCP value on egress traffic from one workload leaving the cluster")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_1.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectNone(extClient, ep1_2)
		cc.CheckConnectivity()

		expectQoSPolicy(tc.Felixes[0], "0x0", toNotExists)
		expectQoSPolicy(tc.Felixes[0], "0x14", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x20", toNotExists)

		expectNoQosPolicy(tc.Felixes[1])

		By("setting the arbitrary DSCP values on other workloads")
		ep2_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp0,
		}
		ep2_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectNone(extClient, ep1_2)
		cc.CheckConnectivity()

		expectQoSPolicy(tc.Felixes[0], "0x0", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x14", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x20", toNotExists)

		expectQoSPolicy(tc.Felixes[1], "0x14", toNotExists)
		expectQoSPolicy(tc.Felixes[1], "0x28", toExists)

		By("updating DSCP values for some of workloads")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp32,
		}
		ep1_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectNone(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectSome(extClient, ep1_2)
		cc.CheckConnectivity()

		expectQoSPolicy(tc.Felixes[0], "0x0", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x14", toNotExists)
		expectQoSPolicy(tc.Felixes[0], "0x20", toExists)

		expectQoSPolicy(tc.Felixes[1], "0x14", toExists)
		expectQoSPolicy(tc.Felixes[1], "0x28", toNotExists)

		By("reverting the expected DSCP on the original workload on felix0 to the expected value")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_1.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectSome(extClient, ep1_2)
		cc.CheckConnectivity()

		expectQoSPolicy(tc.Felixes[0], "0x0", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x14", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x28", toNotExists)

		expectQoSPolicy(tc.Felixes[1], "0x14", toExists)
		expectQoSPolicy(tc.Felixes[1], "0x28", toNotExists)

		By("resetting DSCP value on some workloads")
		ep2_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		ep2_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectNone(extClient, ep1_2)
		cc.CheckConnectivity()

		expectQoSPolicy(tc.Felixes[0], "0x0", toNotExists)
		expectQoSPolicy(tc.Felixes[0], "0x14", toExists)
		expectQoSPolicy(tc.Felixes[0], "0x28", toNotExists)

		expectNoQosPolicy(tc.Felixes[1])

		By("stopping the last workload")
		ep1_1.Stop()
		ep1_1.RemoveFromInfra(infra)

		cc.ResetExpectations()
		cc.ExpectNone(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)
		cc.ExpectNone(extClient, ep1_2)
		cc.CheckConnectivity()

		expectNoQosPolicy(tc.Felixes[0])
		expectNoQosPolicy(tc.Felixes[1])
	})
})

func expectNoQosPolicy(felix *infrastructure.Felix) {
	expectQoSPolicy(felix, "", false)
}

func expectQoSPolicy(felix *infrastructure.Felix, dscp string, expectToExists bool) {
	var (
		cmd         []string
		expectedStr string
	)
	if NFTMode() {
		cmd = []string{"nft", "-n", "list", "chain", "ip", "calico", "mangle-cali-qos-policy"}
		expectedStr = fmt.Sprintf("ip dscp set %v", dscp)
	} else {
		cmd = []string{"iptables-save", "-t", "mangle"}
		expectedStr = fmt.Sprintf("DSCP --set-dscp %v", dscp)
	}
	if expectToExists {
		Eventually(func() string {
			output, _ := felix.ExecOutput(cmd...)
			return output
		}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedStr))
		Consistently(func() string {
			output, _ := felix.ExecOutput(cmd...)
			return output
		}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedStr))
	} else {
		Eventually(func() string {
			output, _ := felix.ExecOutput(cmd...)
			return output
		}, 5*time.Second, 100*time.Millisecond).ShouldNot(ContainSubstring(expectedStr))
		Consistently(func() string {
			output, _ := felix.ExecOutput(cmd...)
			return output
		}, 5*time.Second, 100*time.Millisecond).ShouldNot(ContainSubstring(expectedStr))
	}
}
