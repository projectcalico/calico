// +build fvtests

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"strconv"

	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo/extensions/table"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var _ = Context("Named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {

	var (
		etcd   *containers.Container
		felix  *containers.Container
		client *client.Client
		w      [3]*workload.Workload
	)

	const (
		sharedPortName = "shared-tcp"
		sharedPort     = 1100
		w0Port         = 1000
		w1Port         = 1001
		w2Port         = 1002
	)

	BeforeEach(func() {

		etcd = RunEtcd()

		client = GetEtcdClient(etcd.IP)
		Eventually(client.EnsureInitialized).ShouldNot(HaveOccurred())

		felix = RunFelix(etcd.IP)

		felixNode := api.NewNode()
		felixNode.Metadata.Name = felix.Hostname
		_, err := client.Nodes().Create(felixNode)
		Expect(err).NotTo(HaveOccurred())

		// Install a default profile that allows workloads with this profile to talk to each
		// other, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Metadata.Name = "default"
		defaultProfile.Metadata.Tags = []string{"default"}
		defaultProfile.Spec.EgressRules = []api.Rule{{Action: "allow"}}
		defaultProfile.Spec.IngressRules = []api.Rule{{
			Action: "allow",
			Source: api.EntityRule{Tag: "default"},
		}}
		_, err = client.Profiles().Create(defaultProfile)
		Expect(err).NotTo(HaveOccurred())

		// Create three workloads, using that profile.
		for ii := 0; ii < 3; ii++ {
			iiStr := strconv.Itoa(ii)
			workloadTCPPort := uint16(1000 + ii)
			w[ii] = workload.Run(
				felix,
				"w"+iiStr,
				"cali1"+iiStr,
				"10.65.0.1"+iiStr,
				fmt.Sprintf("3000,4000,1100,%d", workloadTCPPort),
			)

			w[ii].WorkloadEndpoint.Spec.Ports = []api.EndpointPort{
				{
					Port:     sharedPort,
					Name:     sharedPortName,
					Protocol: numorstring.ProtocolFromString("tcp"),
				},
				{
					Port:     workloadTCPPort,
					Name:     fmt.Sprintf("w%d-tcp", ii),
					Protocol: numorstring.ProtocolFromString("tcp"),
				},
				{
					Port:     2200,
					Name:     "shared-udp",
					Protocol: numorstring.ProtocolFromString("udp"),
				},
				{
					Port:     uint16(1000 + ii),
					Name:     fmt.Sprintf("w%d-udp", ii),
					Protocol: numorstring.ProtocolFromString("udp"),
				},
			}
			w[ii].Configure(client)
		}
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			log.Warn("Test failed, dumping diags...")
			utils.Run("docker", "logs", felix.Name)
			utils.Run("docker", "exec", felix.Name, "iptables-save", "-c")
			utils.Run("docker", "exec", felix.Name, "ipset", "list")
			utils.Run("docker", "exec", felix.Name, "ip", "r")
		}

		for ii := 0; ii < 3; ii++ {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			utils.Run("docker", "exec", etcd.Name, "etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	type ingressEgress int
	const (
		ingress ingressEgress = iota
		egress
	)

	// Baseline test with no named ports policy.
	Context("with no named port policy", func() {
		It("should give full connectivity to and from workload 0", func() {
			var cc = &workload.ConnectivityChecker{}

			// Outbound, w0 should be able to reach all ports on w1 & w2
			cc.ExpectSome(w[0], w[1], sharedPort)
			cc.ExpectSome(w[0], w[2], sharedPort)
			cc.ExpectSome(w[0], w[1], w1Port)
			cc.ExpectSome(w[0], w[2], w2Port)

			cc.ExpectNone(w[0], w[2], 9999) // Not a port we open

			// Inbound, w1 and w2 should be able to reach all ports on w0.
			cc.ExpectSome(w[1], w[0], sharedPort)
			cc.ExpectSome(w[2], w[0], sharedPort)
			cc.ExpectSome(w[1], w[0], w0Port)
			cc.ExpectSome(w[2], w[0], w0Port)
			cc.ExpectSome(w[1], w[0], 4000)
			cc.ExpectSome(w[2], w[0], 4000)

			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
		})
	})

	createPolicy := func(policy *api.Policy) {
		log.WithField("policy", policy).Info("Creating policy")
		_, err := client.Policies().Create(policy)
		Expect(err).NotTo(HaveOccurred())
	}

	buildSharedPortPolicy := func(negated bool, ie ingressEgress, numNumericPorts int, useDestSel bool) *api.Policy {
		protoTCP := numorstring.ProtocolFromString("tcp")
		policy := api.NewPolicy()
		policy.Metadata.Name = "policy-1"
		ports := []numorstring.Port{
			numorstring.NamedPort(sharedPortName),
		}
		for i := 0; i < numNumericPorts; i++ {
			ports = append(ports, numorstring.SinglePort(3000+uint16(i)))
		}
		entRule := api.EntityRule{}
		if negated {
			entRule.NotPorts = ports
		} else {
			entRule.Ports = ports
		}
		if useDestSel {
			entRule.Selector = w[0].NameSelector()
		}
		apiRule := api.Rule{
			Action:      "allow",
			Protocol:    &protoTCP,
			Destination: entRule,
		}
		rules := []api.Rule{
			apiRule,
		}
		if ie == ingress {
			// Ingress rules, apply only to w[0].
			policy.Spec.IngressRules = rules
			policy.Spec.Selector = w[0].NameSelector()
		} else {
			// Egress rules, to get same result, apply everywhere but w[0].
			policy.Spec.EgressRules = rules
			policy.Spec.Selector = fmt.Sprintf("!(%s)", w[0].NameSelector())
		}
		return policy
	}

	DescribeTable("with a policy that matches on the shared named port",
		// negated controls whether we put the named port in the Ports or NotPorts list.
		//
		// ingressOrEgress controls whether we render the policy as an ingress policy of w[0]
		//                 or an egress policy on all the other workloads.
		//
		// numNumericPorts controls the number of extra numeric ports we include in the list.
		//
		// useDestSel if set, adds a destination selector (picking out w[0]) to the rule.
		func(negated bool, ingressOrEgress ingressEgress, numNumericPorts int, useDestSel bool) {
			pol := buildSharedPortPolicy(negated, ingressOrEgress, numNumericPorts, useDestSel)
			createPolicy(pol)

			var cc = &workload.ConnectivityChecker{}

			if negated {
				// Only traffic _not_ going to listed ports is allowed.

				// Shared port is listed so w1 and w2 should not be able to reach the shared port
				// on w0.
				cc.ExpectNone(w[1], w[0], sharedPort)
				cc.ExpectNone(w[2], w[0], sharedPort)
				// Inbound to w0 port should still be allowed.
				cc.ExpectSome(w[1], w[0], w0Port)
				cc.ExpectSome(w[2], w[0], w0Port)
				// Inbound to unlisted numeric should still be allowed.
				cc.ExpectSome(w[1], w[0], 4000)
				cc.ExpectSome(w[2], w[0], 4000)

				if numNumericPorts > 0 {
					cc.ExpectNone(w[1], w[0], 3000)
				} else {
					cc.ExpectSome(w[1], w[0], 3000)
				}
			} else {
				// Only traffic to listed ports is allowed.

				// Inbound to w0Port should now be blocked.
				cc.ExpectNone(w[1], w[0], w0Port)
				cc.ExpectNone(w[2], w[0], w0Port)

				// Inbound to unlisted numeric should now be blocked.
				cc.ExpectNone(w[1], w[0], 4000)
				cc.ExpectNone(w[2], w[0], 4000)

				// w1 and w2 should still be able to reach the shared port on w0.
				cc.ExpectSome(w[1], w[0], sharedPort)
				cc.ExpectSome(w[2], w[0], sharedPort)

				if numNumericPorts > 0 {
					cc.ExpectSome(w[1], w[0], 3000)
				} else {
					cc.ExpectNone(w[1], w[0], 3000)
				}
			}

			if ingressOrEgress == egress {
				// When we render the policy at egress, we can piggy-back some additional tests
				// on the connectivity between w[1] and w[2].
				if useDestSel {
					// We're limiting the destination to the w[0] pod so there should be no
					// connectivity between w[1] and w[2].  Test a couple of sample paths:
					cc.ExpectNone(w[1], w[2], sharedPort)
					cc.ExpectNone(w[2], w[1], w1Port)
				} else if negated {
					// We're not using the destination selector but the port list is negated so
					// we're explicitly excluding the shared port.
					cc.ExpectNone(w[1], w[2], sharedPort)
					cc.ExpectSome(w[1], w[2], w2Port)
				} else {
					// Positive policy with no destination selector, should allow the shared port.
					cc.ExpectSome(w[1], w[2], sharedPort)
					cc.ExpectNone(w[2], w[1], w1Port)
				}
			} else {
				// Policy being applied at ingress on w[0], shouldn't affect w[1] <-> w[2]
				// connectivity.
				cc.ExpectSome(w[1], w[2], w2Port)
				cc.ExpectSome(w[2], w[1], sharedPort)
			}

			// Outbound, w0 should be able to reach all ports on w1 & w2
			cc.ExpectSome(w[0], w[1], sharedPort)
			cc.ExpectSome(w[0], w[2], sharedPort)
			cc.ExpectSome(w[0], w[1], w1Port)
			cc.ExpectSome(w[0], w[2], w2Port)

			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
		},

		// Non-negated named port match.  The rule will allow traffic to the named port.

		// No numeric ports in the rule, the IP set match will be rendered in the main rule.
		Entry("(positive) ingress, no-numeric", false, ingress, 0, false),
		Entry("(positive) egress, no-numeric", false, egress, 0, false),
		// Adding a numeric port changes the way we render iptables rules to use blocks.
		Entry("(positive) ingress, 1 numeric", false, ingress, 1, false),
		Entry("(positive) egress, 1 numeric", false, egress, 1, false),
		// Adding >15 numeric ports requires more than one block.
		Entry("(positive) ingress, 16 numeric", false, ingress, 16, false),
		Entry("(positive) egress, 16 numeric", false, egress, 16, false),

		// Negated named port match.  The rule will not match traffic to the named port (so traffic
		// to the named port will fall through to the default deny rule).

		// No numeric ports in the rule, the IP set match will be rendered in the main rule.
		Entry("(negated) ingress, no-numeric", true, ingress, 0, false),
		Entry("(negated) egress, no-numeric", true, egress, 0, false),
		// Adding a numeric port changes the way we render iptables rules to use blocks.
		Entry("(negated) ingress, 1 numeric", true, ingress, 1, false),
		Entry("(negated) egress, 1 numeric", true, egress, 1, false),
		// Adding >15 numeric ports requires more than one block.
		Entry("(negated) ingress, 16 numeric", true, ingress, 16, false),
		Entry("(negated) egress, 16 numeric", true, egress, 16, false),

		// Selection of tests that include a destination selector too.
		Entry("(positive) egress, no-numeric with a dest selector", false, egress, 0, true),
		Entry("(positive) egress, 16 numeric with a dest selector", false, egress, 16, true),
		Entry("(negated) egress, no-numeric with a dest selector", true, egress, 0, true),
		Entry("(negated) egress, 16 numeric with a dest selector", true, egress, 16, true),
	)
})
