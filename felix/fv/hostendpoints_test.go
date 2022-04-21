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
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ named host endpoints",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		describeHostEndpointTests(getInfra, false)
	})

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ all-interfaces host endpoints",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		describeHostEndpointTests(getInfra, true)
	})

// describeHostEndpointTests describes tests exercising host endpoints.
// If allInterfaces, then interfaceName: "*". Otherwise, interfaceName: "eth0".
func describeHostEndpointTests(getInfra infrastructure.InfraFactory, allInterfaces bool) {
	var (
		bpfEnabled       = os.Getenv("FELIX_FV_ENABLE_BPF") == "true"
		infra            infrastructure.DatastoreInfra
		felixes          []*infrastructure.Felix
		client           client.Interface
		w                [2]*workload.Workload
		hostW            [2]*workload.Workload
		rawIPHostW253    [2]*workload.Workload
		rawIPHostW254    [2]*workload.Workload
		cc, cc253, cc254 *connectivity.Checker // Numbered checkers are for raw IP tests of specific protocols.
	)

	BeforeEach(func() {
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.IPIPEnabled = false
		options.WithTypha = true
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)

		// Create workloads, using that profile. One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInInfra(infra)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
			rawIPHostW253[ii] = workload.Run(felixes[ii], fmt.Sprintf("raw-host%d", ii), "", felixes[ii].IP, "", "ip4:253")
			rawIPHostW254[ii] = workload.Run(felixes[ii], fmt.Sprintf("raw-host%d", ii), "", felixes[ii].IP, "", "ip4:254")
		}

		cc = &connectivity.Checker{}
		cc253 = &connectivity.Checker{Protocol: "ip4:253"}
		cc254 = &connectivity.Checker{Protocol: "ip4:254"}
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

		for _, wl := range w {
			wl.Stop()
		}
		for _, wl := range hostW {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentSpecReport().Failed() {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	expectHostToHostTraffic := func() {
		cc.ExpectSome(felixes[0], hostW[1])
		cc.ExpectSome(felixes[1], hostW[0])
	}
	expectHostToOtherPodTraffic := func() {
		// host to other pod
		cc.ExpectSome(felixes[0], w[1])
		cc.ExpectSome(felixes[1], w[0])
	}
	expectHostToOwnPodTraffic := func() {
		// host to own pod always allowed
		cc.ExpectSome(felixes[0], w[0])
		cc.ExpectSome(felixes[1], w[1])
	}
	expectHostToOwnPodViaServiceTraffic := func() {
		// host to own pod always allowed, even via a service IP
		for i := range felixes {
			// Allocate a service IP.
			serviceIP := fmt.Sprintf("10.96.0.%v", i+1)

			// Add a NAT rule for the service IP.
			felixes[i].ProgramIptablesDNAT(serviceIP, w[i].IP, "OUTPUT")

			// Expect connectivity to the service IP.
			cc.ExpectSome(felixes[i], connectivity.TargetIP(serviceIP), 8055)
		}
	}
	expectDenyHostToRemotePodViaServiceTraffic := func() {
		// host to remote pod always denied, even via a service IP
		for i := range felixes {
			// Allocate a service IP.
			serviceIP := fmt.Sprintf("10.96.10.%v", i+1)

			// Add a NAT rule for the service IP.
			felixes[i].ProgramIptablesDNAT(serviceIP, w[1-i].IP, "OUTPUT")

			// Expect not to be able to connect to the service IP.
			cc.ExpectNone(felixes[i], connectivity.TargetIP(serviceIP), 8055)
		}
	}
	expectPodToPodTraffic := func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
	}
	expectLocalPodToRemotePodViaServiceTraffic := func() {
		for i := range felixes {
			// Allocate a service IP.
			serviceIP := fmt.Sprintf("10.96.10.%v", i+1)

			// Add a NAT rule for the service IP.
			felixes[i].ProgramIptablesDNAT(serviceIP, w[1-i].IP, "PREROUTING")

			// Expect to connect from local pod to the service IP.
			cc.ExpectSome(w[i], connectivity.TargetIP(serviceIP), 8055)
		}
	}
	expectDenyHostToHostTraffic := func() {
		cc.ExpectNone(felixes[0], hostW[1])
		cc.ExpectNone(felixes[1], hostW[0])
	}
	expectDenyHostToOtherPodTraffic := func() {
		cc.ExpectNone(felixes[0], w[1])
		cc.ExpectNone(felixes[1], w[0])
	}
	expectConnectivityToAPIServer := func() {
		ip := connectivity.TargetIP(infra.(*infrastructure.K8sDatastoreInfra).EndpointIP)
		cc.ExpectSome(felixes[0], ip, 6443)
		cc.ExpectSome(felixes[1], ip, 6443)
	}
	expectConnectivityToTypha := func() {
		typhaIP1 := connectivity.TargetIP(felixes[0].TyphaIP)
		typhaIP2 := connectivity.TargetIP(felixes[1].TyphaIP)
		cc.ExpectSome(felixes[0], typhaIP1, 5473)
		cc.ExpectSome(felixes[1], typhaIP2, 5473)
	}

	Context("_BPF-SAFE_ with no policies and no profiles on the host endpoints", func() {
		BeforeEach(func() {

			// Install a default profile that allows all pod ingress and egress, in the absence of any policy.
			infra.AddDefaultAllow()

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "hep-" + f.Name
				hep.Labels = map[string]string{
					"name":          hep.Name,
					"hostname":      f.Hostname,
					"host-endpoint": "true",
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				if allInterfaces {
					hep.Spec.InterfaceName = "*"
				} else {
					hep.Spec.InterfaceName = "eth0"
				}
				_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				if bpfEnabled {
					Eventually(f.NumTCBPFProgsEth0, "5s", "200ms").Should(Equal(2))
				}
			}

			// Wait for HEPs to become active.
			expectDenyHostToHostTraffic()
			cc.CheckConnectivity()
			cc.ResetExpectations()
		})

		It("should block raw IP", func() {
			cc253.Expect(connectivity.None, felixes[0], rawIPHostW253[1])
			cc253.Expect(connectivity.None, felixes[1], rawIPHostW253[0])
			cc254.Expect(connectivity.None, felixes[0], rawIPHostW254[1])
			cc254.Expect(connectivity.None, felixes[1], rawIPHostW254[0])
			cc253.CheckConnectivity()
			cc254.CheckConnectivity()
		})

		It("should allow connectivity from nodes to the Kubernetes API server", func() {
			expectConnectivityToAPIServer()
			cc.CheckConnectivity()
		})

		It("should allow connectivity from nodes to Typha", func() {
			expectConnectivityToTypha()
			cc.CheckConnectivity()
		})

		It("should allow pod-to-pod traffic", func() {
			// Wait for HEPs to become active.
			expectDenyHostToHostTraffic()
			cc.CheckConnectivity()
			cc.ResetExpectations()
			// Check the workload traffic still gets through.
			cc.Expect(connectivity.Some, w[0], w[1])
			cc.CheckConnectivity()
		})

		It("should block all traffic except pod-to-pod and host-to-own-pod traffic", func() {
			expectDenyHostToHostTraffic()
			expectDenyHostToOtherPodTraffic()
			expectPodToPodTraffic()
			expectHostToOwnPodTraffic()
			if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
				// These tests use iptables to implement a simulated service, which doesn't work in BPF mode.
				// TODO-HEP: implement proper services for BPF mode
				expectHostToOwnPodViaServiceTraffic()
				expectDenyHostToRemotePodViaServiceTraffic()
				expectLocalPodToRemotePodViaServiceTraffic()
			}
			cc.CheckConnectivity()
		})

		It("should allow felixes[0] => felixes[1] traffic if ingress and egress policies are in place", func() {
			// Create a policy selecting felix[0] that allows egress.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "f0-egress"
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// But no policy allowing ingress into felix[1].
			cc.ExpectNone(felixes[0], hostW[1])

			// No policy allowing egress from felixes[1] nor ingress into
			// felixes[0]
			cc.ExpectNone(felixes[1], w[0])
			cc.ExpectNone(felixes[1], hostW[0])

			expectPodToPodTraffic()
			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()
			cc.ResetExpectations()

			// Should block raw IP too.
			By("Blocking raw IP from felix[0] <-> felix[1]")
			cc253.Expect(connectivity.None, felixes[0], rawIPHostW253[1])
			cc253.Expect(connectivity.None, felixes[1], rawIPHostW253[0])
			cc253.CheckConnectivity()
			cc253.ResetExpectations()

			// Now add a policy selecting felix[1] that allows ingress.
			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "f1-ingress"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Now felixes[0] can reach felixes[1].
			cc.ExpectSome(felixes[0], hostW[1])

			// But not traffic the other way.
			cc.ExpectNone(felixes[1], hostW[0])

			expectPodToPodTraffic()
			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()

			// Need to test this first because the conntrack is symmetric for portless protocols.
			By("Blocking raw IP from felix[1] -> felix[0]")
			cc253.Expect(connectivity.None, felixes[1], rawIPHostW253[0])
			cc253.CheckConnectivity()
			cc253.ResetExpectations()

			By("Allowing raw IP from felix[0] -> felix[1]")
			cc253.Expect(connectivity.Some, felixes[0], rawIPHostW253[1])
			cc253.CheckConnectivity()
		})

		It("should allow raw IP with the right protocol only", func() {
			// Create a policy selecting felix[0] that allows egress.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "f0-egress"
			proto253 := numorstring.ProtocolFromInt(253)
			policy.Spec.Egress = []api.Rule{{
				Action:   api.Allow,
				Protocol: &proto253,
			}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Should block all raw IP until we have the second policy in place.
			By("Blocking raw IP from felix[0] <-> felix[1]")
			cc253.Expect(connectivity.None, felixes[0], rawIPHostW253[1])
			cc253.Expect(connectivity.None, felixes[1], rawIPHostW253[0])
			cc253.CheckConnectivity()
			cc253.ResetExpectations()
			cc254.Expect(connectivity.None, felixes[0], rawIPHostW254[1])
			cc254.Expect(connectivity.None, felixes[1], rawIPHostW254[0])
			cc254.CheckConnectivity()

			// Now add a policy selecting felix[1] that allows ingress.
			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "f1-ingress"
			policy.Spec.Ingress = []api.Rule{{
				Action:   api.Allow,
				Protocol: &proto253,
			}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// One-way check because conntrack for unknown protocols is symmetric so, once the
			// felix[0] -> felix[1] packet goes through, we expect felix[1] -> felix[0] to work too
			// (and the connectivity checker always does a request-response to check that).
			cc253.Expect(connectivity.Some, felixes[0], rawIPHostW253[1])
			cc253.CheckConnectivity()

			// 254 should still be blocked...
			cc254.CheckConnectivity()
		})

		It("should not deny host-to-own pod traffic even if an apply-on-forward deny policy is applied", func() {
			// Create an AOF policy denying all traffic on the host endpoints.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "aof-deny"
			policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Selector = "has(host-endpoint)"
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			expectDenyHostToHostTraffic()
			expectDenyHostToOtherPodTraffic()
			expectPodToPodTraffic()
			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()
		})
	})

	Context("with no policies and an allow-all profile on the host endpoints", func() {
		BeforeEach(func() {
			// Install a default profile that allows all pod ingress and egress, in the absence of any policy.
			defaultProfileName := infra.AddDefaultAllow()

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "hep-" + f.Name
				hep.Labels = map[string]string{
					"name":          hep.Name,
					"hostname":      f.Hostname,
					"host-endpoint": "true",
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				if allInterfaces {
					hep.Spec.InterfaceName = "*"
				} else {
					hep.Spec.InterfaceName = "eth0"
				}
				hep.Spec.Profiles = []string{defaultProfileName}
				_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should allow all traffic", func() {
			expectHostToHostTraffic()
			expectHostToOtherPodTraffic()
			expectHostToOwnPodTraffic()
			expectPodToPodTraffic()
			cc.CheckConnectivity()
		})

		It("should deny felixes[0] => felixes[1] traffic if policy denies egress from felixes[0]", func() {
			// Create a policy selecting felix[1] that denies egress.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "f0-egress"
			policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Egress from felixes[0] denied
			cc.ExpectNone(felixes[0], hostW[1])
			cc.ExpectNone(felixes[0], w[1])

			// Egress from felixes[1] allowed
			cc.ExpectSome(felixes[1], hostW[0])
			cc.ExpectSome(felixes[1], w[0])

			expectHostToOwnPodTraffic()
			expectPodToPodTraffic()
			cc.CheckConnectivity()
		})

		Context("with a policy denying ingress on felixes[1]", func() {
			BeforeEach(func() {
				// Create a policy selecting felix[1] that denies ingress.
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "f1-ingress"
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should deny felixes[0] => felixes[1] traffic if policy denies ingress on felixes[1]", func() {
				// Egress from felixes[1] is allowed
				cc.ExpectSome(felixes[1], hostW[0])
				cc.ExpectSome(felixes[1], w[0])

				// Ingress into felixes[1] denied
				cc.ExpectNone(felixes[0], hostW[1])

				// Forwarded traffic to felixes[1] is allowed
				cc.ExpectSome(felixes[0], w[1])

				expectHostToOwnPodTraffic()
				expectPodToPodTraffic()
				cc.CheckConnectivity()
			})
		})

		It("should deny forwarded traffic from felixes[0] to felixes[1] if an AOF policy denies it", func() {

			// Create an apply-on-forward policy selecting felix[1] that
			// - only allows ingress from its own pod
			// - allows all egress
			//
			// Note that AOF policy on all-interfaces host endpoints will result in
			// the ingress and egress policy boundaries being enforced.
			//
			// E.g. forwarded traffic from w[1] out of eth0 will need to pass:
			// - egress policy on w[1]
			// - AOF ingress policy on the all-interfaces HEP
			// - AOF egress policy on the all-interfaces HEP

			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "aof-f1"
			policy.Spec.Ingress = []api.Rule{
				{
					Action: api.Allow,
					Source: api.EntityRule{
						Selector: fmt.Sprintf("name == '%s'", w[1].WorkloadEndpoint.Labels["name"]),
					},
				},
			}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
			policy.Spec.ApplyOnForward = true
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "aof-f0"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
			policy.Spec.ApplyOnForward = true
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Ingress into felixes[1] denied
			cc.ExpectNone(felixes[0], hostW[1])

			// Because of the AOF policy, forwarded traffic to felixes[1] is blocked.
			cc.ExpectNone(felixes[0], w[1])
			cc.ExpectNone(w[0], w[1])

			// Forwarded traffic the other way should be unaffected
			cc.ExpectSome(w[1], w[0])

			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()
		})
	})
}
