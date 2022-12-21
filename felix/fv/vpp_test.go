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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/fv/utils"
	wepapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"math"
	"time"

	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/sirupsen/logrus"
)

var _ = infrastructure.DatastoreDescribe("vpp topology", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra       infrastructure.DatastoreInfra
		felix       *infrastructure.Felix
		client      client.Interface
		gnp         *api.GlobalNetworkPolicy
		hep         *api.HostEndpoint
		felixConfig *api.FelixConfiguration
		log         *logrus.Logger
		err         error
		vpp         *vpplink.VppLink
	)

	const (
		VPPContainerName      = "cni-tests-vpp"
		testTimeout           = "20s"
		vppInterfacesPolicies = "show capo int"
		vppPolicies           = "show capo policies verbose"
		vppCnatSnat           = "show cnat snat-policy"
		hepSelector           = "test == \"heptest\""
		wepSelector           = "test == \"weptest\""
	)

	Describe(fmt.Sprint("Using external dataplane driver vpp"), func() {
		Context("With one node topology (one felix)", func() {
			BeforeEach(func() {
				felixConfig = api.NewFelixConfiguration()
			})
			JustBeforeEach(func() {
				log = logrus.New()
				// connect to VPP
				timeout := 20 * time.Second
				retry := 100 * time.Millisecond
				maxRetry := int(math.Round(float64(timeout.Nanoseconds() / retry.Nanoseconds())))
				for i := 0; i < maxRetry; i++ {
					vpp, err = vpplink.NewVppLink("/tmp/"+VPPContainerName+"/vpp-api-test.sock", log.WithFields(logrus.Fields{"component": "vpp-api"}))
					if err != nil {
						if i < (maxRetry / 2) {
							/* do not warn, it is probably fine */
							log.Infof("Waiting for VPP... [%d/%d]", i, maxRetry)
						} else {
							log.Warnf("Waiting for VPP... [%d/%d] %v", i, maxRetry, err)
						}
						time.Sleep(retry)
					} else {
						// Try a simple API message to verify everything is up and running
						version, err := vpp.GetVPPVersion()
						if err != nil {
							log.Warnf("Try [%d/%d] broken vpplink: %v", i, maxRetry, err)
							time.Sleep(retry)
						} else {
							log.Infof("Connected to VPP version %s", version)
							break
						}
					}
				}
				Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Cannot create VPP client: %v", err))
				Expect(vpp).NotTo(BeNil())

				infra = getInfra()
				topologyOptions := infrastructure.DefaultTopologyOptions()
				felixConfig.SetName("default")
				topologyOptions.InitialFelixConfiguration = felixConfig
				fal := false
				topologyOptions.InitialFelixConfiguration.Spec.UseInternalDataplaneDriver = &fal
				topologyOptions.InitialFelixConfiguration.Spec.DataplaneDriver = "/usr/local/bin/felix-api-proxy"

				felix, client = infrastructure.StartSingleNodeTopology(topologyOptions, infra)
				hep = api.NewHostEndpoint()
				hep.Name = "hep-" + felix.Name
				hep.Labels = map[string]string{
					"name":          hep.Name,
					"hostname":      felix.Hostname,
					"host-endpoint": "true",
					"test":          "heptest",
				}
				hep.Spec.Node = felix.Hostname
				hep.Spec.InterfaceName = "uplink"
				gnp = api.NewGlobalNetworkPolicy()
				gnp.Name = "np-" + felix.Name
				gnp.Spec.Selector = hepSelector
				gnp.Spec.Egress = []api.Rule{api.Rule{Action: "Allow", Destination: api.EntityRule{Nets: []string{"1.9.9.1/32"}}}}
			})
			AfterEach(func() {
				felix.Stop()
				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})
			Context("With Felix Configuration fields", func() {
				Context("Changing EndpointToHostAction", func() {
					BeforeEach(func() {
						felixConfig.Spec.DefaultEndpointToHostAction = "Accept"
					})
					It("should change default endpoint to host action to Accept", func() {
						Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring(";allow][src==[ipset#0"))
					})
				})
				Context("Changing failsafe policies", func() {
					BeforeEach(func() {
						ports := []api.ProtoPort{}
						felixConfig.Spec.FailsafeOutboundHostPorts = &ports
						felixConfig.Spec.FailsafeInboundHostPorts = &ports
					})
					It("should change failsafe policies to empty lists", func() {
						Eventually(vpp.RunCli, testTimeout).WithArguments(vppPolicies).ShouldNot(ContainSubstring("#4]\n  tx"))
					})
				})
			})
			Context("With Host endpoint creation", func() {
				It("should create a host endpoint with a policy not on forward", func() {
					_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					gnp.Spec.Selector = hepSelector
					gnp.Spec.ApplyOnForward = false
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					// uplink should be empty
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("invertedaddr=10.0.100.0]\n["))
					// vpptap should have policy applied
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("allow][dst==1.9.9.1/32,]"))
					// should have failsafe policies
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring(";allow][proto==TCP,dst==179,dst==2379,dst==2380,dst==5473,dst==6443,dst==6666,dst==6667,]"))
				})
				It("should create a host endpoint with a policy on forward", func() {
					_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					gnp.Spec.Selector = hepSelector
					gnp.Spec.ApplyOnForward = true
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("allow][dst==1.9.9.1/32,]"))
				})
				It("should create an empty host endpoint", func() {
					_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("invertedaddr=10.0.100.0]\n["))
				})
				It("should create a wildcard host endpoint", func() {
					hep.Spec.InterfaceName = "*"
					_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("[tap0 sw_if_index=1 invertedaddr=10.0.100.0]"))
				})
				It("should create a host endpoint with a policy then update its policy", func() {
					_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					gnp.Spec.Selector = hepSelector
					gnp.Spec.ApplyOnForward = false
					gnp, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					// vpptap should have policy applied
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("allow][dst==1.9.9.1/32,]"))
					gnp.Spec.Egress = []api.Rule{api.Rule{Action: "Allow", Destination: api.EntityRule{Nets: []string{"1.9.7.7/32"}}}}
					_, err = client.GlobalNetworkPolicies().Update(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					// should have the policy updated
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("allow][dst==1.9.7.7/32,]"))
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).ShouldNot(ContainSubstring("1.9.9.1"))
				})
			})
			Context("With different policies contents", func() {
				It("should use UDP protocol and 8055 port", func() {
					_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					gnp.Spec.Selector = hepSelector
					protocol := numorstring.ProtocolFromString("UDP")
					gnp.Spec.Egress = []api.Rule{api.Rule{Action: "Deny", Protocol: &protocol, Destination: api.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(8055)}}}}
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring(";deny][proto==UDP,dst==8055,]"))
				})
			})
			Context("With Workload endpoint creation", func() {
				const (
					ipAddress   = "1.2.3.44"
					wepSelector = "name == \"wepvpptest\""
				)
				JustBeforeEach(func() {
					pod := podCreation("wepvpptest", felix)
					pod.Start()
					pod.ConfigureInInfra(infra)
				})
				It("should create a pod and configure default profiles", func() {
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("addr=" + ipAddress + "]\n  profiles"))
				})
				It("should create a policy and apply it to the pod", func() {
					gnp.Spec.Selector = wepSelector
					_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("addr=" + ipAddress))
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("1.9.9.1"))
				})
				It("should select a pod as destination using a rule selector in host policy", func() {
					_, err = client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					gnp.Spec.Selector = hepSelector
					gnp.Spec.Egress = []api.Rule{api.Rule{Action: "Deny", Source: api.EntityRule{Selector: wepSelector}}}
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppInterfacesPolicies).Should(ContainSubstring("prefix;1.2.3.44"))
				})
			})
			Context("With ipam pools", func() {
				It("should add and delete snat prefix when ippool is created/deleted", func() {
					ippool := api.NewIPPool()
					ippool.Name = "nat-pool"
					ippool.Spec.CIDR = "10.244.255.0/24"
					ippool.Spec.NATOutgoing = true
					By("creating ippool and checking snat")
					ippool, err = client.IPPools().Create(utils.Ctx, ippool, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppCnatSnat).Should(ContainSubstring("10.244.255.0/24"))
					By("deleting ippool and checking snat")
					_, err = client.IPPools().Delete(utils.Ctx, ippool.Name, options.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(vpp.RunCli, testTimeout).WithArguments(vppCnatSnat).ShouldNot(ContainSubstring("10.244.255.0/24"))
				})
			})
		})
	})
})

// this function is created to replace the one in fv/workload which gives a random index name to the pod
// this function allows to specify the pod name for sync purposes with cni server from calico vpp side
func podCreation(n string, c *infrastructure.Felix) *workload.Workload {
	ipAddress := "1.2.3.44"
	wep := wepapi.NewWorkloadEndpoint()
	wep.Namespace = "fv"
	wep.Labels = map[string]string{"name": n}
	wep.Spec.Node = c.Hostname
	wep.Spec.Orchestrator = "felixfv"
	wep.Spec.Workload = n
	wep.Spec.Endpoint = n
	wep.Spec.IPNetworks = []string{ipAddress + "/32"}
	wep.Spec.InterfaceName = "eth0"
	wep.Spec.Profiles = []string{"default"}
	pod := &workload.Workload{
		C:                c.Container,
		Name:             n,
		InterfaceName:    "eth0",
		IP:               ipAddress,
		Ports:            "12345",
		Protocol:         "tcp",
		WorkloadEndpoint: wep,
		MTU:              1450,
	}
	c.Workloads = append(c.Workloads, pod)
	return pod
}
