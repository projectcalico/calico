// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
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
		tc               infrastructure.TopologyContainers
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
		options.IPIPMode = api.IPIPModeNever
		options.WithTypha = true
		tc, client = infrastructure.StartNNodeTopology(2, options, infra)

		// Create workloads, using that profile. One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInInfra(infra)

			hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
			rawIPHostW253[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("raw-host%d", ii), "", tc.Felixes[ii].IP, "", "ip4:253")
			rawIPHostW254[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("raw-host%d", ii), "", tc.Felixes[ii].IP, "", "ip4:254")
		}

		cc = &connectivity.Checker{}
		cc253 = &connectivity.Checker{Protocol: "ip4:253"}
		cc254 = &connectivity.Checker{Protocol: "ip4:254"}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				if NFTMode() {
					logNFTDiags(felix)
				}
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
		tc.Stop()

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	expectHostToHostTraffic := func() {
		cc.ExpectSome(tc.Felixes[0], hostW[1])
		cc.ExpectSome(tc.Felixes[1], hostW[0])
	}
	expectHostToOtherPodTraffic := func() {
		// host to other pod
		cc.ExpectSome(tc.Felixes[0], w[1])
		cc.ExpectSome(tc.Felixes[1], w[0])
	}
	expectHostToOwnPodTraffic := func() {
		// host to own pod always allowed
		cc.ExpectSome(tc.Felixes[0], w[0])
		cc.ExpectSome(tc.Felixes[1], w[1])
	}
	expectHostToOwnPodViaServiceTraffic := func() {
		port := 8055
		tgtPort := 8055
		// host to own pod always allowed, even via a service IP
		for i := range tc.Felixes {
			// Allocate a service IP.
			serviceIP := fmt.Sprintf("10.101.0.%v", i+20)
			svcName := fmt.Sprintf("test-svc-%v", i+20)

			createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
				infra:     infra,
				felix:     tc.Felixes[i],
				w:         w[i],
				svcName:   svcName,
				serviceIP: serviceIP,
				targetIP:  w[i].IP,
				port:      port,
				tgtPort:   tgtPort,
				chain:     "OUTPUT",
			})

			// Expect connectivity to the service IP.
			cc.ExpectSome(tc.Felixes[i], connectivity.TargetIP(serviceIP), uint16(port))
		}
	}

	expectDenyHostToRemotePodViaServiceTraffic := func() {
		port := 8055
		tgtPort := 8055
		// host to remote pod always denied, even via a service IP
		for i := range tc.Felixes {
			// Allocate a service IP.
			serviceIP := fmt.Sprintf("10.101.10.%v", i+10)
			svcName := fmt.Sprintf("test-svc-%v", i+10)

			createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
				infra:     infra,
				felix:     tc.Felixes[i],
				w:         w[1-i],
				svcName:   svcName,
				serviceIP: serviceIP,
				targetIP:  w[1-i].IP,
				port:      port,
				tgtPort:   tgtPort,
				chain:     "OUTPUT",
			})

			// Expect not to be able to connect to the service IP.
			cc.ExpectNone(tc.Felixes[i], connectivity.TargetIP(serviceIP), uint16(port))
		}
	}

	expectPodToPodTraffic := func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
	}

	expectLocalPodToRemotePodViaServiceTraffic := func() {
		port := 8055
		tgtPort := 8055
		for i := range tc.Felixes {
			// Allocate a service IP.
			serviceIP := fmt.Sprintf("10.101.10.%v", i)
			svcName := fmt.Sprintf("test-svc-%v", i)
			createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
				infra:     infra,
				felix:     tc.Felixes[i],
				w:         w[1-i],
				svcName:   svcName,
				serviceIP: serviceIP,
				targetIP:  w[1-i].IP,
				port:      port,
				tgtPort:   tgtPort,
				chain:     "PREROUTING",
			})

			// Expect to connect from local pod to the service IP.
			cc.ExpectSome(w[i], connectivity.TargetIP(serviceIP), uint16(port))
		}
	}

	expectDenyHostToHostTraffic := func() {
		cc.ExpectNone(tc.Felixes[0], hostW[1])
		cc.ExpectNone(tc.Felixes[1], hostW[0])
	}
	expectDenyHostToOtherPodTraffic := func() {
		cc.ExpectNone(tc.Felixes[0], w[1])
		cc.ExpectNone(tc.Felixes[1], w[0])
	}
	expectConnectivityToAPIServer := func() {
		ip := connectivity.TargetIP(infra.(*infrastructure.K8sDatastoreInfra).EndpointIP)
		cc.ExpectSome(tc.Felixes[0], ip, 6443)
		cc.ExpectSome(tc.Felixes[1], ip, 6443)
	}
	expectConnectivityToTypha := func() {
		typhaIP1 := connectivity.TargetIP(tc.Felixes[0].TyphaIP)
		typhaIP2 := connectivity.TargetIP(tc.Felixes[1].TyphaIP)
		cc.ExpectSome(tc.Felixes[0], typhaIP1, 5473)
		cc.ExpectSome(tc.Felixes[1], typhaIP2, 5473)
	}

	Context("_BPF-SAFE_ with no policies and no profiles on the host endpoints", func() {
		BeforeEach(func() {
			// Install a default profile that allows all pod ingress and egress, in the absence of any policy.
			infra.AddDefaultAllow()

			for _, f := range tc.Felixes {
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
					Eventually(f.NumTCBPFProgsEth0, "30s", "200ms").Should(Equal(2))
				}
			}

			// Wait for HEPs to become active.
			expectDenyHostToHostTraffic()
			cc.CheckConnectivity()
			cc.ResetExpectations()
		})

		It("should block raw IP", func() {
			cc253.Expect(connectivity.None, tc.Felixes[0], rawIPHostW253[1])
			cc253.Expect(connectivity.None, tc.Felixes[1], rawIPHostW253[0])
			cc254.Expect(connectivity.None, tc.Felixes[0], rawIPHostW254[1])
			cc254.Expect(connectivity.None, tc.Felixes[1], rawIPHostW254[0])
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
			if !NFTMode() {
				expectHostToOwnPodViaServiceTraffic()
			}
			expectDenyHostToRemotePodViaServiceTraffic()
			expectLocalPodToRemotePodViaServiceTraffic()
			cc.CheckConnectivity()
		})

		It("should allow containers.Felix[0] => containers.Felix[1] traffic if ingress and egress policies are in place", func() {
			// Create a "security" tier.  We had a bug in Enterprise Felix that wrongly
			// hardcoded the "default" tier name, and most of the tests in this file use
			// "default" because of having originated in OSS.  This test is modified to
			// use a non-default tier name, and also to do a policy update, so as to
			// cover that bug scenario.
			securityTier := api.NewTier()
			securityTier.Name = "security"
			order := float64(10.0)
			securityTier.Spec = api.TierSpec{
				Order: &order,
			}
			_, err := client.Tiers().Create(utils.Ctx, securityTier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy selecting felix[0] that allows egress.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "security.f0-egress"
			policy.Spec.Tier = "security"
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[0].Hostname)
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// But no policy allowing ingress into felix[1].
			cc.ExpectNone(tc.Felixes[0], hostW[1])

			// No policy allowing egress from containers.Felix[1] nor ingress into
			// containers.Felix[0]
			cc.ExpectNone(tc.Felixes[1], w[0])
			cc.ExpectNone(tc.Felixes[1], hostW[0])

			expectPodToPodTraffic()
			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()
			cc.ResetExpectations()

			// Should block raw IP too.
			By("Blocking raw IP from felix[0] <-> felix[1]")
			cc253.Expect(connectivity.None, tc.Felixes[0], rawIPHostW253[1])
			cc253.Expect(connectivity.None, tc.Felixes[1], rawIPHostW253[0])
			cc253.CheckConnectivity()
			cc253.ResetExpectations()

			// Now add a policy selecting felix[1] that allows ingress.
			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "security.f1-ingress"
			policy.Spec.Tier = "security"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[1].Hostname)
			policy, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Now containers.Felix[0] can reach containers.Felix[1].
			cc.ExpectSome(tc.Felixes[0], hostW[1])

			// But not traffic the other way.
			cc.ExpectNone(tc.Felixes[1], hostW[0])

			expectPodToPodTraffic()
			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()

			// Need to test this first because the conntrack is symmetric for portless protocols.
			By("Blocking raw IP from felix[1] -> felix[0]")
			cc253.Expect(connectivity.None, tc.Felixes[1], rawIPHostW253[0])
			cc253.CheckConnectivity()
			cc253.ResetExpectations()

			By("Allowing raw IP from felix[0] -> felix[1]")
			cc253.Expect(connectivity.Some, tc.Felixes[0], rawIPHostW253[1])
			cc253.CheckConnectivity()

			// Change the f1-ingress policy to Deny.
			policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			_, err = client.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Now containers.Felix[0] should NOT be able to reach containers.Felix[1].
			cc.ResetExpectations()
			cc.ExpectNone(tc.Felixes[0], hostW[1])
			cc.CheckConnectivity()
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
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Should block all raw IP until we have the second policy in place.
			By("Blocking raw IP from felix[0] <-> felix[1]")
			cc253.Expect(connectivity.None, tc.Felixes[0], rawIPHostW253[1])
			cc253.Expect(connectivity.None, tc.Felixes[1], rawIPHostW253[0])
			cc253.CheckConnectivity()
			cc253.ResetExpectations()
			cc254.Expect(connectivity.None, tc.Felixes[0], rawIPHostW254[1])
			cc254.Expect(connectivity.None, tc.Felixes[1], rawIPHostW254[0])
			cc254.CheckConnectivity()

			// Now add a policy selecting felix[1] that allows ingress.
			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "f1-ingress"
			policy.Spec.Ingress = []api.Rule{{
				Action:   api.Allow,
				Protocol: &proto253,
			}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[1].Hostname)
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// One-way check because conntrack for unknown protocols is symmetric so, once the
			// felix[0] -> felix[1] packet goes through, we expect felix[1] -> felix[0] to work too
			// (and the connectivity checker always does a request-response to check that).
			cc253.Expect(connectivity.Some, tc.Felixes[0], rawIPHostW253[1])
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

			for _, f := range tc.Felixes {
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
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[0].Hostname)
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Egress from containers.Felix[0] denied
			cc.ExpectNone(tc.Felixes[0], hostW[1])
			cc.ExpectNone(tc.Felixes[0], w[1])

			// Egress from containers.Felix[1] allowed
			cc.ExpectSome(tc.Felixes[1], hostW[0])
			cc.ExpectSome(tc.Felixes[1], w[0])

			expectHostToOwnPodTraffic()
			expectPodToPodTraffic()
			cc.CheckConnectivity()
		})

		Context("with a policy denying ingress on containers.Felix[1]", func() {
			BeforeEach(func() {
				// Create a policy selecting felix[1] that denies ingress.
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "f1-ingress"
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[1].Hostname)
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should deny felixes[0] => felixes[1] traffic if policy denies ingress on felixes[1]", func() {
				// Egress from containers.Felix[1] is allowed
				cc.ExpectSome(tc.Felixes[1], hostW[0])
				cc.ExpectSome(tc.Felixes[1], w[0])

				// Ingress into containers.Felix[1] denied
				cc.ExpectNone(tc.Felixes[0], hostW[1])

				// Forwarded traffic to containers.Felix[1] is allowed
				cc.ExpectSome(tc.Felixes[0], w[1])

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
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[1].Hostname)
			policy.Spec.ApplyOnForward = true
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			policy = api.NewGlobalNetworkPolicy()
			policy.Name = "aof-f0"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[0].Hostname)
			policy.Spec.ApplyOnForward = true
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Ingress into containers.Felix[1] denied
			cc.ExpectNone(tc.Felixes[0], hostW[1])

			// Because of the AOF policy, forwarded traffic to containers.Felix[1] is blocked.
			cc.ExpectNone(tc.Felixes[0], w[1])
			cc.ExpectNone(w[0], w[1])

			// Forwarded traffic the other way should be unaffected
			cc.ExpectSome(w[1], w[0])

			expectHostToOwnPodTraffic()
			cc.CheckConnectivity()
		})
	})
}

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ with IP forwarding disabled",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		var (
			infra  infrastructure.DatastoreInfra
			tc     infrastructure.TopologyContainers
			client client.Interface
			w      [2]*workload.Workload
			hostW  [2]*workload.Workload
			cc     *connectivity.Checker // Numbered checkers are for raw IP tests of specific protocols.
		)

		BeforeEach(func() {
			infra = getInfra()
			options := infrastructure.DefaultTopologyOptions()
			options.DelayFelixStart = true
			options.IPIPMode = api.IPIPModeNever
			options.WithTypha = true
			options.ExtraEnvVars["FELIX_IPFORWARDING"] = "Disabled"
			tc, client = infrastructure.StartNNodeTopology(2, options, infra)
			_ = client

			// Create workloads, using that profile. One on each "host".
			for ii := range w {
				wIP := fmt.Sprintf("10.65.%d.2", ii)
				wName := fmt.Sprintf("w%d", ii)
				w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
				w[ii].ConfigureInInfra(infra)

				hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
			}

			for _, f := range tc.Felixes {
				// The IP forwarding setting gets inherited from the host so we
				// need to disable it before felix starts in order to test the
				// feature.
				f.Exec("sysctl", "-w", "net.ipv4.ip_forward=0")
				f.TriggerDelayedStart()
			}

			cc = &connectivity.Checker{}
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				for _, felix := range tc.Felixes {
					if NFTMode() {
						logNFTDiags(felix)
					}
					felix.Exec("iptables-save", "-c")
					felix.Exec("ipset", "list")
					felix.Exec("ip", "r")
					felix.Exec("ip", "a")
					felix.Exec("sysctl", "-a")
				}
			}

			for _, wl := range w {
				wl.Stop()
			}
			for _, wl := range hostW {
				wl.Stop()
			}
			tc.Stop()

			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		if BPFMode() {
			It("should force IPForward to Enabled", func() {
				// Our RPF check fails in BPF mode if IP forwarding is disabled
				// so we force-enable it for now.
				cc.Expect(connectivity.Some, tc.Felixes[0], hostW[1])
				cc.Expect(connectivity.Some, tc.Felixes[1], hostW[0])
				cc.Expect(connectivity.Some, tc.Felixes[0], w[0])
				cc.Expect(connectivity.Some, tc.Felixes[1], w[1])
				cc.Expect(connectivity.Some, tc.Felixes[0], w[1])
				cc.Expect(connectivity.Some, tc.Felixes[1], w[0])
				cc.Expect(connectivity.Some, w[0], w[1])
				cc.Expect(connectivity.Some, w[0], w[1])
				cc.CheckConnectivity()

				// Check that the sysctl really is enabled.
				for _, f := range tc.Felixes {
					Expect(f.ExecOutput("sysctl", "-n", "net.ipv4.ip_forward")).To(Equal("1\n"))
				}
			})

			Describe("with BPFEnforceRPF set to Disabled", func() {
				BeforeEach(func() {
					infrastructure.UpdateFelixConfiguration(client, func(configuration *api.FelixConfiguration) {
						configuration.Spec.BPFEnforceRPF = "Disabled"
					})
				})

				It("should have host-to-host and host-to-local connectivity only", func() {
					cc.Expect(connectivity.Some, tc.Felixes[0], hostW[1])
					cc.Expect(connectivity.Some, tc.Felixes[1], hostW[0])
					cc.Expect(connectivity.Some, tc.Felixes[0], w[0])
					cc.Expect(connectivity.Some, tc.Felixes[1], w[1])
					cc.Expect(connectivity.None, tc.Felixes[0], w[1])
					cc.Expect(connectivity.None, tc.Felixes[1], w[0])
					cc.Expect(connectivity.None, w[0], w[1])
					cc.Expect(connectivity.None, w[0], w[1])
					cc.CheckConnectivity()

					// Check that the sysctl really is disabled.
					for _, f := range tc.Felixes {
						Expect(f.ExecOutput("sysctl", "-n", "net.ipv4.ip_forward")).To(Equal("0\n"))
					}
				})
			})
		} else {
			It("should have host-to-host and host-to-local connectivity only", func() {
				cc.Expect(connectivity.Some, tc.Felixes[0], hostW[1])
				cc.Expect(connectivity.Some, tc.Felixes[1], hostW[0])
				cc.Expect(connectivity.Some, tc.Felixes[0], w[0])
				cc.Expect(connectivity.Some, tc.Felixes[1], w[1])
				cc.Expect(connectivity.None, tc.Felixes[0], w[1])
				cc.Expect(connectivity.None, tc.Felixes[1], w[0])
				cc.Expect(connectivity.None, w[0], w[1])
				cc.Expect(connectivity.None, w[0], w[1])
				cc.CheckConnectivity()

				// Check that the sysctl really is disabled.
				for _, f := range tc.Felixes {
					Expect(f.ExecOutput("sysctl", "-n", "net.ipv4.ip_forward")).To(Equal("0\n"))
				}
			})
		}
	})
