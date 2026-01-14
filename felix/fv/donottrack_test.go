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
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/ifstate"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ do-not-track policy tests; with 2 nodes", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra          infrastructure.DatastoreInfra
		tc             infrastructure.TopologyContainers
		hostW          [2]*workload.Workload
		client         client.Interface
		cc             *Checker
		externalClient *containers.Container
		ctx            context.Context
		cancel         context.CancelFunc
	)

	BeforeEach(func() {
		var err error
		iOpts := []infrastructure.CreateOption{}
		if BPFMode() {
			iOpts = append(iOpts,
				infrastructure.K8sWithDualStack(),
				infrastructure.K8sWithAPIServerBindAddress("::"),
				infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112,10.101.0.0/16"))
		}
		infra = getInfra(iOpts...)
		options := infrastructure.DefaultTopologyOptions()
		if BPFMode() {
			options.EnableIPv6 = true
			options.ExtraEnvVars["FELIX_BPFLogLevel"] = "debug"
			options.IPIPMode = api.IPIPModeNever
		}
		tc, client = infrastructure.StartNNodeTopology(2, options, infra)
		cc = &Checker{}

		// Start a host networked workload on each host for connectivity checks.
		for ii := range tc.Felixes {
			// We tell each workload to open:
			// - its normal (uninteresting) port, 8055
			// - port 2379, which is both an inbound and an outbound failsafe port
			// - port 22, which is an inbound failsafe port.
			// This allows us to test the interaction between do-not-track policy and failsafe
			// ports.
			const portsToOpen = "8055,2379,22"
			hostW[ii] = workload.Run(
				tc.Felixes[ii],
				fmt.Sprintf("host%d", ii),
				"default",
				tc.Felixes[ii].IP, // Same IP as felix means "run in the host's namespace"
				portsToOpen,
				"tcp", workload.WithIPv6Address(tc.Felixes[ii].IPv6))
		}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		externalClient = infrastructure.RunExtClient(infra, "ext-client")
		err = infra.AddDefaultDeny()
		Expect(err).To(BeNil())
	})

	expectFullConnectivity := func(opts ...ExpectationOption) {
		cc.ResetExpectations()
		cc.Expect(Some, tc.Felixes[0], hostW[1].Port(8055), opts...)
		cc.Expect(Some, tc.Felixes[1], hostW[0].Port(8055), opts...)
		cc.Expect(Some, tc.Felixes[0], hostW[1].Port(2379), opts...)
		cc.Expect(Some, tc.Felixes[1], hostW[0].Port(2379), opts...)
		cc.Expect(Some, tc.Felixes[0], hostW[1].Port(22), opts...)
		cc.Expect(Some, tc.Felixes[1], hostW[0].Port(22), opts...)
		cc.Expect(Some, externalClient, hostW[1].Port(22), opts...)
		cc.Expect(Some, externalClient, hostW[0].Port(22), opts...)
		cc.CheckConnectivityOffset(1)
	}

	expectFailSafeOnlyConnectivity := func(opts ...ExpectationOption) {
		cc.ResetExpectations()
		cc.Expect(None, tc.Felixes[0], hostW[1].Port(8055), opts...)
		cc.Expect(None, tc.Felixes[1], hostW[0].Port(8055), opts...)
		cc.Expect(Some, tc.Felixes[0], hostW[1].Port(2379), opts...)
		cc.Expect(Some, tc.Felixes[1], hostW[0].Port(2379), opts...)
		// Port 22 is inbound-only so it'll be blocked by the (lack of egress policy).
		cc.Expect(None, tc.Felixes[0], hostW[1].Port(22), opts...)
		cc.Expect(None, tc.Felixes[1], hostW[0].Port(22), opts...)
		// But external client should still be able to access it...
		cc.Expect(Some, externalClient, hostW[1].Port(22), opts...)
		cc.Expect(Some, externalClient, hostW[0].Port(22), opts...)
		cc.CheckConnectivityOffset(1)
	}

	expectFailSafeOnlyConnectivityWithHost0 := func(opts ...ExpectationOption) {
		cc.ResetExpectations()
		cc.Expect(None, tc.Felixes[0], hostW[1].Port(8055), opts...)
		cc.Expect(None, tc.Felixes[1], hostW[0].Port(8055), opts...)
		cc.Expect(Some, tc.Felixes[0], hostW[1].Port(2379), opts...)
		cc.Expect(Some, tc.Felixes[1], hostW[0].Port(2379), opts...)
		// Port 22 is inbound-only so it'll be blocked by the (lack of egress policy).
		cc.Expect(None, tc.Felixes[0], hostW[1].Port(22), opts...)
		cc.Expect(Some, tc.Felixes[1], hostW[0].Port(22), opts...)
		// But external client should still be able to access it...
		cc.Expect(Some, externalClient, hostW[1].Port(22), opts...)
		cc.Expect(Some, externalClient, hostW[0].Port(22), opts...)
		cc.CheckConnectivityOffset(1)
	}

	testDonotTrackPolicy := func(iface string) {
		// This test covers both normal connectivity and failsafe connectivity.  We combine the
		// tests because we rely on the changes of normal connectivity at each step to make sure
		// that the policy has actually flowed through to the dataplane.

		By("having only failsafe connectivity to start with")
		expectFailSafeOnlyConnectivity()

		if BPFMode() {
			expectFailSafeOnlyConnectivity(ExpectWithIPVersion(6))
			By("Having no Linux IP sets")
			Consistently(tc.Felixes[0].IPSetNames, "2s", "1s").Should(BeEmpty())
		}

		host0Selector := fmt.Sprintf("name == '%s-%s'", iface, tc.Felixes[0].Name)
		host1Selector := fmt.Sprintf("name == '%s-%s'", iface, tc.Felixes[1].Name)

		By("Having connectivity after installing bidirectional policies")
		host0Pol := createDonotTrackPolicy("host-0-pol", host0Selector, host1Selector, client, ctx)
		_ = createDonotTrackPolicy("host-1-pol", host1Selector, host0Selector, client, ctx)

		if iface == "bond0" {
			Consistently(xdpProgramAttached(tc.Felixes[0], "bond0"), "2s", "1s").Should(BeFalse())
			Consistently(xdpProgramAttached(tc.Felixes[1], "bond0"), "2s", "1s").Should(BeFalse())
			Eventually(xdpProgramAttached(tc.Felixes[0], "eth0"), "10s", "1s").Should(BeTrue())
			Eventually(xdpProgramAttached(tc.Felixes[1], "eth0"), "10s", "1s").Should(BeTrue())
		}

		expectFullConnectivity()
		if BPFMode() {
			expectFullConnectivity(ExpectWithIPVersion(6))
			By("Having a Linux IP set for the egress policy")

			elems := []string{
				utils.IPSetNameForSelector(4, host1Selector),
				utils.IPSetNameForSelector(6, host1Selector),
			}
			if NFTMode() {
				// NFT uses a different prefixing scheme, since the ":" character is not allowed.
				// e.g., cali40- instead of cali40:
				for i, elem := range elems {
					elems[i] = strings.Replace(elem, ":", "-", 1)
				}
			}
			Expect(tc.Felixes[0].IPSetNames()).To(ContainElements(elems))
		}

		By("Having only failsafe connectivity after removing host-0's egress rule")
		// Since there's no conntrack, removing rules in one direction is enough to prevent
		// connectivity in either direction.
		host0Pol.Spec.Egress = []api.Rule{}
		host0Pol, err := client.GlobalNetworkPolicies().Update(ctx, host0Pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		expectFailSafeOnlyConnectivityWithHost0()
		if BPFMode() {
			expectFailSafeOnlyConnectivityWithHost0(ExpectWithIPVersion(6))
		}

		By("Having full connectivity after putting them back")
		host0Pol.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
				Destination: api.EntityRule{
					Selector: host1Selector,
				},
			},
		}
		host0Pol, err = client.GlobalNetworkPolicies().Update(ctx, host0Pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		expectFullConnectivity()
		if BPFMode() {
			expectFullConnectivity(ExpectWithIPVersion(6))
		}

		By("Having only failsafe connectivity after replacing host-0's ingress rules with Deny")
		host0Pol.Spec.Ingress = []api.Rule{
			{
				Action: api.Deny,
				Destination: api.EntityRule{
					Selector: host0Selector,
				},
			},
		}
		host0Pol, err = client.GlobalNetworkPolicies().Update(ctx, host0Pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		expectFailSafeOnlyConnectivityWithHost0()
		if BPFMode() {
			expectFailSafeOnlyConnectivityWithHost0(ExpectWithIPVersion(6))
		}
	}

	It("before adding policy, should have connectivity between hosts", func() {
		expectFullConnectivity()
		if BPFMode() {
			expectFullConnectivity(ExpectWithIPVersion(6))
		}
	})

	Context("after adding host endpoints", func() {
		BeforeEach(func() {
			// Make sure our new host endpoints don't cut felix off from the datastore.
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel = context.WithTimeout(context.Background(), 50*time.Second)

			for _, f := range tc.Felixes {
				createHostEndpoint(f, "eth0", []string{f.IP, f.IPv6}, client, ctx)
			}
			if BPFMode() {
				ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgHEP, nil)
				ensureRightIFStateFlags(tc.Felixes[1], ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgHEP, nil)
			}
		})

		AfterEach(func() {
			cancel()
		})

		It("should implement untracked policy correctly", func() {
			testDonotTrackPolicy("eth0")
		})

		if BPFMode() {
			Describe("with a custom map size", func() {
				BeforeEach(func() {
					newRtSize := 1000
					newNATFeSize := 2000
					newNATBeSize := 3000
					newNATAffSize := 4000
					newIpSetMapSize := 5000
					newCtMapSize := 6000
					infrastructure.UpdateFelixConfiguration(client, func(cfg *api.FelixConfiguration) {
						cfg.Spec.BPFMapSizeRoute = &newRtSize
						cfg.Spec.BPFMapSizeNATFrontend = &newNATFeSize
						cfg.Spec.BPFMapSizeNATBackend = &newNATBeSize
						cfg.Spec.BPFMapSizeNATAffinity = &newNATAffSize
						cfg.Spec.BPFMapSizeIPSets = &newIpSetMapSize
						cfg.Spec.BPFMapSizeConntrack = &newCtMapSize
					})
				})

				It("should implement untracked policy correctly", func() {
					testDonotTrackPolicy("eth0")
				})
			})
		}
	})

	Context("after adding eth0 to a bond interface", func() {
		if !BPFMode() {
			return
		}

		BeforeEach(func() {
			// Make sure our new host endpoints don't cut felix off from the datastore.
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel = context.WithTimeout(context.Background(), 50*time.Second)
			for _, felix := range tc.Felixes {
				// recreate those after moving the IP.
				defaultRoute, err := felix.ExecOutput("ip", "route", "show", "default")
				Expect(err).NotTo(HaveOccurred())
				lines := strings.Split(strings.Trim(defaultRoute, "\n "), "\n")
				Expect(lines).To(HaveLen(1))
				defaultRouteArgs := strings.Split(strings.ReplaceAll(lines[0], "eth0", "bond0"), " ")

				// Assuming the subnet route will be "proto kernel" and that will be the only such route.
				subnetRoute, err := felix.ExecOutput("ip", "route", "show", "proto", "kernel")
				Expect(err).NotTo(HaveOccurred())
				lines = strings.Split(strings.Trim(subnetRoute, "\n "), "\n")
				Expect(lines).To(HaveLen(1), "expected only one proto kernel route, has docker's routing set-up changed?")
				subnetArgs := strings.Split(strings.ReplaceAll(lines[0], "eth0", "bond0"), " ")

				// Move IPv6
				defaultRoute6, err := felix.ExecOutput("ip", "-6", "route", "show", "default")
				Expect(err).NotTo(HaveOccurred())
				lines = strings.Split(strings.Trim(defaultRoute6, "\n "), "\n")
				Expect(lines).To(HaveLen(1))
				defaultRoute6Args := strings.Split(strings.ReplaceAll(lines[0], "eth0", "bond0"), " ")

				// Assuming the subnet route will be "proto kernel" and that will be the only such route.
				subnetRoute6, err := felix.ExecOutput("ip", "-6", "route", "show", "proto", "kernel")
				Expect(err).NotTo(HaveOccurred())
				lines = strings.Split(strings.Trim(subnetRoute6, "\n "), "\n")
				subnet6Args := strings.Split(strings.ReplaceAll(lines[0], "eth0", "bond0"), " ")

				felix.Exec("ip", "addr", "del", felix.IP, "dev", "eth0")
				ip6WithSubnet := felix.IPv6 + "/" + felix.GetIPv6Prefix()
				felix.Exec("ip", "-6", "addr", "del", ip6WithSubnet, "dev", "eth0")

				felix.Exec("ip", "link", "add", "dev", "bond0", "type", "bond")
				felix.Exec("ip", "link", "set", "dev", "eth0", "down")
				felix.Exec("ip", "link", "set", "dev", "eth0", "master", "bond0")
				felix.Exec("ip", "link", "set", "dev", "eth0", "up")
				felix.Exec("ip", "link", "set", "dev", "bond0", "up")

				ipWithSubnet := felix.IP + "/" + felix.GetIPPrefix()
				felix.Exec("ip", "addr", "add", ipWithSubnet, "dev", "bond0")
				felix.Exec(append([]string{"ip", "r", "add"}, defaultRouteArgs...)...)
				felix.Exec(append([]string{"ip", "r", "replace"}, subnetArgs...)...)

				felix.Exec("ip", "-6", "addr", "add", ip6WithSubnet, "dev", "bond0")
				felix.Exec(append([]string{"ip", "-6", "r", "add"}, defaultRoute6Args...)...)
				felix.Exec(append([]string{"ip", "-6", "r", "replace"}, subnet6Args...)...)

				ensureRightIFStateFlags(felix, ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgBondSlave, map[string]uint32{"bond0": ifstate.FlgIPv4Ready | ifstate.FlgIPv6Ready | ifstate.FlgBond})
				createHostEndpoint(felix, "bond0", []string{felix.IP, felix.IPv6}, client, ctx)
			}

			for _, felix := range tc.Felixes {
				Eventually(func() bool {
					return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, "bond0", "egress", "allow-egress", "allow", false)
				}, "5s", "200ms").Should(BeTrue())

				Eventually(func() bool {
					return bpfCheckIfGlobalNetworkPolicyProgrammedV6(felix, "bond0", "egress", "allow-egress", "allow", false)
				}, "5s", "200ms").Should(BeTrue())

			}
		})

		AfterEach(func() {
			cancel()
		})
		It("should implement untracked policy correctly", func() {
			testDonotTrackPolicy("bond0")
		})
	})
})

func createHostEndpoint(f *infrastructure.Felix, iface string,
	expectedIPs []string, client client.Interface, ctx context.Context,
) {
	hep := api.NewHostEndpoint()
	hep.Name = iface + "-" + f.Name
	hep.Labels = map[string]string{
		"name":          hep.Name,
		"host-endpoint": "true",
	}
	hep.Spec.Node = f.Hostname
	hep.Spec.InterfaceName = iface
	hep.Spec.ExpectedIPs = expectedIPs
	_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func createDonotTrackPolicy(name, selector, dstSelector string, client client.Interface, ctx context.Context) *api.GlobalNetworkPolicy {
	pol := api.NewGlobalNetworkPolicy()
	pol.Name = name
	pol.Spec.Selector = selector
	pol.Spec.DoNotTrack = true
	pol.Spec.ApplyOnForward = true
	pol.Spec.Ingress = []api.Rule{
		{
			Action: api.Allow,
			Source: api.EntityRule{
				Selector: dstSelector,
			},
		},
	}
	pol.Spec.Egress = []api.Rule{
		{
			Action: api.Allow,
			Destination: api.EntityRule{
				Selector: dstSelector,
			},
		},
	}
	pol, err := client.GlobalNetworkPolicies().Create(ctx, pol, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
	return pol
}
