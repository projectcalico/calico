// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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
	"net"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
)

var _ = infrastructure.DatastoreDescribe("IPv6 iptables tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	if BPFMode() {
		return
	}

	var (
		infra        infrastructure.DatastoreInfra
		tc           infrastructure.TopologyContainers
		calicoClient client.Interface
		cc           *Checker
		options      infrastructure.TopologyOptions
	)

	BeforeEach(func() {
		options = infrastructure.DefaultTopologyOptions()
		options.EnableIPv6 = true
		options.FelixLogSeverity = "Debug"
		options.IPIPEnabled = false

		iOpts := []infrastructure.CreateOption{
			infrastructure.K8sWithIPv6(),
			infrastructure.K8sWithAPIServerBindAddress("::"),
			infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112"),
		}

		infra = getInfra(iOpts...)

		cc = &Checker{
			CheckSNAT: true,
			Protocol:  "tcp",
		}
	})

	JustAfterEach(func() {
		if CurrentSpecReport().Failed() {
			for _, felix := range tc.Felixes {
				felix.Exec("conntrack", "-L")
				felix.Exec("ip6tables-save", "-c")
				felix.Exec("ip", "-6", "link")
				felix.Exec("ip", "-6", "addr")
				felix.Exec("ip", "-6", "rule")
				felix.Exec("ip", "-6", "route")
				felix.Exec("ip", "-6", "route", "show", "table", "1")
				felix.Exec("ip", "-6", "neigh")
			}
		}
	})

	AfterEach(func() {
		log.Info("AfterEach starting")
		for _, f := range tc.Felixes {
			f.Stop()
		}
		log.Info("AfterEach done")
	})

	AfterEach(func() {
		infra.Stop()
	})

	var (
		w [2][2]*workload.Workload
	)

	setupCluster := func() {
		tc, calicoClient = infrastructure.StartNNodeTopology(2, options, infra)

		addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
			if labels == nil {
				labels = make(map[string]string)
			}

			wIP := net.ParseIP(fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)).String()
			wName := fmt.Sprintf("w%d%d", ii, wi)

			w := workload.New(tc.Felixes[ii], wName, "default",
				wIP, strconv.Itoa(port), "tcp")

			labels["name"] = w.Name

			w.WorkloadEndpoint.Labels = labels
			if run {
				err := w.Start()
				Expect(err).NotTo(HaveOccurred())
				w.ConfigureInInfra(infra)
			}
			if options.UseIPPools {
				// Assign the workload's IP in IPAM, this will trigger calculation of routes.
				err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
					IP:       cnet.MustParseIP(wIP),
					HandleID: &w.Name,
					Attrs: map[string]string{
						ipam.AttributeNode: tc.Felixes[ii].Hostname,
					},
					Hostname: tc.Felixes[ii].Hostname,
				})
				Expect(err).NotTo(HaveOccurred())
			}

			return w
		}

		// Start a host networked workload on each host for connectivity checks.
		for ii := range tc.Felixes {
			// Two workloads on each host so we can check the same host and other host cases.
			w[ii][0] = addWorkload(true, ii, 0, 8055, nil)
			w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
		}
	}

	createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Creating policy")
		policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}

	Describe("with a 2 node cluster", func() {
		BeforeEach(func() {
			setupCluster()
		})

		It("should have connectivity from all workloads via workload 0's main IP when ICMPv6 is blocked", func() {
			nets := []string{"::/0"}
			icmpProto := numorstring.ProtocolFromString("icmpv6")

			pol := api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "deny-icmp-v6"
			pol.Spec.Selector = "all()"
			pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: nets,
					},
				},
				{
					Action:   "Deny",
					Protocol: &icmpProto,
				},
			}
			pol.Spec.Egress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: nets,
					},
				},
				{
					Action:   "Deny",
					Protocol: &icmpProto,
				},
			}

			pol = createPolicy(pol)

			By("Syncing with policy that blocks ICMPv6")
			rulesProgrammed := func() bool {
				out0, err := tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				out1, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				if strings.Count(out0, pol.Name) == 0 {
					return false
				}
				if strings.Count(out1, pol.Name) == 0 {
					return false
				}
				return true
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")

			By("Testing connectivity - it requires some ICMPv6")
			cc.ExpectSome(w[0][1], w[0][0])
			cc.ExpectSome(w[1][0], w[0][0])
			cc.ExpectSome(w[1][1], w[0][0])
			cc.CheckConnectivity()
		})
	})
})
