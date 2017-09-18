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
	"encoding/json"
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var _ = Context("Destination named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(false)
})
var _ = Context("Source named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(true)
})

// describeNamedPortTests describes tests for either source or destination named ports.
// If testSourcePorts is true then the direction of all the connectivity tests is flipped.
// The set-up and policy generation is parametrised:
//
//     - If testSourcePorts is true then the workloads only open a single target port so that we
//       can use the named ports as sources.  Otherwise, they open all the named ports as
//       listeners.
//
//     - The policy generation is parametrised to move the match criteria from destination port
//       to source port (and from ingress/egress to the opposite) if the flag is set.
func describeNamedPortTests(testSourcePorts bool) {

	var (
		etcd   *containers.Container
		felix  *containers.Container
		client *client.Client
		w      [4]*workload.Workload
		cc     *workload.ConnectivityChecker
	)

	const (
		sharedPortName = "shared-tcp"
		w0PortName     = "w0-tcp"
		w1PortName     = "w1-tcp"
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
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			workloadTCPPort := uint16(1000 + ii)

			var ports string
			if testSourcePorts {
				ports = "10000"
			} else {
				ports = fmt.Sprintf("3000,4000,1100,%d", workloadTCPPort)
			}
			w[ii] = workload.Run(
				felix,
				"w"+iiStr,
				"cali0"+iiStr,
				"10.65.0.1"+iiStr,
				ports,
			)

			// Includes some named ports on each workload.  Each workload gets its own named port,
			// which is unique and a shared one.
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
			w[ii].DefaultPort = "10000"
			w[ii].Configure(client)
		}

		cc = &workload.ConnectivityChecker{
			ReverseDirection: testSourcePorts,
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
		applyAtW0 ingressEgress = iota
		applyAtOthers
	)

	// Baseline test with no named ports policy.
	Context("with no named port policy", func() {
		It("should give full connectivity to and from workload 0", func() {
			// Outbound, w0 should be able to reach all ports on w1 & w2
			cc.ExpectSome(w[0], w[1].Port(sharedPort))
			cc.ExpectSome(w[0], w[2].Port(sharedPort))
			cc.ExpectSome(w[0], w[1].Port(w1Port))
			cc.ExpectSome(w[0], w[2].Port(w2Port))

			if !testSourcePorts {
				cc.ExpectNone(w[0], w[2].Port(9999)) // Not a port we open
			}

			// Inbound, w1 and w2 should be able to reach all ports on w0.
			cc.ExpectSome(w[1], w[0].Port(sharedPort))
			cc.ExpectSome(w[2], w[0].Port(sharedPort))
			cc.ExpectSome(w[1], w[0].Port(w0Port))
			cc.ExpectSome(w[2], w[0].Port(w0Port))
			cc.ExpectSome(w[1], w[0].Port(4000))
			cc.ExpectSome(w[2], w[0].Port(4000))

			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
		})
	})

	createPolicy := func(policy *api.Policy) {
		log.WithField("policy", policy).Info("Creating policy")
		_, err := client.Policies().Create(policy)
		Expect(err).NotTo(HaveOccurred())
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
		func(negated bool, applyRulesAt ingressEgress, numNumericPorts int, useDestSel bool) {
			protoTCP := numorstring.ProtocolFromString("tcp")
			pol := api.NewPolicy()
			pol.Metadata.Name = "policy-1"
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
				Action:   "allow",
				Protocol: &protoTCP,
			}
			if testSourcePorts {
				apiRule.Source = entRule
			} else {
				apiRule.Destination = entRule
			}
			rules := []api.Rule{
				apiRule,
			}

			if applyRulesAt == applyAtW0 {
				pol.Spec.Selector = w[0].NameSelector()
				if testSourcePorts {
					pol.Spec.EgressRules = rules
				} else {
					pol.Spec.IngressRules = rules
				}
			} else {
				pol.Spec.Selector = fmt.Sprintf("!(%s)", w[0].NameSelector())
				if testSourcePorts {
					pol.Spec.IngressRules = rules
				} else {
					pol.Spec.EgressRules = rules
				}
			}

			createPolicy(pol)

			if negated {
				// Only traffic _not_ going to listed ports is allowed.

				// Shared port is listed so w1 and w2 should not be able to reach the shared port
				// on w0.
				cc.ExpectNone(w[1], w[0].Port(sharedPort))
				cc.ExpectNone(w[2], w[0].Port(sharedPort))
				// Inbound to w0 port should still be allowed.
				cc.ExpectSome(w[1], w[0].Port(w0Port))
				cc.ExpectSome(w[2], w[0].Port(w0Port))
				// Inbound to unlisted numeric should still be allowed.
				cc.ExpectSome(w[1], w[0].Port(4000))
				cc.ExpectSome(w[2], w[0].Port(4000))

				if numNumericPorts > 0 {
					cc.ExpectNone(w[1], w[0].Port(3000))
				} else {
					cc.ExpectSome(w[1], w[0].Port(3000))
				}
			} else {
				// Only traffic to listed ports is allowed.

				// Inbound to w0Port should now be blocked.
				cc.ExpectNone(w[1], w[0].Port(w0Port))
				cc.ExpectNone(w[2], w[0].Port(w0Port))

				// Inbound to unlisted numeric should now be blocked.
				cc.ExpectNone(w[1], w[0].Port(4000))
				cc.ExpectNone(w[2], w[0].Port(4000))

				// w1 and w2 should still be able to reach the shared port on w0.
				cc.ExpectSome(w[1], w[0].Port(sharedPort))
				cc.ExpectSome(w[2], w[0].Port(sharedPort))

				if numNumericPorts > 0 {
					cc.ExpectSome(w[1], w[0].Port(3000))
				} else {
					cc.ExpectNone(w[1], w[0].Port(3000))
				}
			}

			if applyRulesAt == applyAtOthers {
				// When we render the policy at egress, we can piggy-back some additional tests
				// on the connectivity between w[1] and w[2].
				if useDestSel {
					// We're limiting the destination to the w[0] pod so there should be no
					// connectivity between w[1] and w[2].  Test a couple of sample paths:
					cc.ExpectNone(w[1], w[2].Port(sharedPort))
					cc.ExpectNone(w[2], w[1].Port(w1Port))
				} else if negated {
					// We're not using the destination selector but the port list is negated so
					// we're explicitly excluding the shared port.
					cc.ExpectNone(w[1], w[2].Port(sharedPort))
					cc.ExpectSome(w[1], w[2].Port(w2Port))
				} else {
					// Positive policy with no destination selector, should allow the shared port.
					cc.ExpectSome(w[1], w[2].Port(sharedPort))
					cc.ExpectNone(w[2], w[1].Port(w1Port))
				}
			} else {
				// Policy being applied at ingress on w[0], shouldn't affect w[1] <-> w[2]
				// connectivity.
				cc.ExpectSome(w[1], w[2].Port(w2Port))
				cc.ExpectSome(w[2], w[1].Port(sharedPort))
			}

			// Outbound, w0 should be able to reach all ports on w1 & w2
			cc.ExpectSome(w[0], w[1].Port(sharedPort))
			cc.ExpectSome(w[0], w[2].Port(sharedPort))
			cc.ExpectSome(w[0], w[1].Port(w1Port))
			cc.ExpectSome(w[0], w[2].Port(w2Port))

			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
				Equal(cc.ExpectedConnectivity()),
				dumpPolicy(pol),
			)
		},

		// Non-negated named port match.  The rule will allow traffic to the named port.

		// No numeric ports in the rule, the IP set match will be rendered in the main rule.
		Entry("(positive) ingress, no-numeric", false, applyAtW0, 0, false),
		Entry("(positive) egress, no-numeric", false, applyAtOthers, 0, false),
		// Adding a numeric port changes the way we render iptables rules to use blocks.
		Entry("(positive) ingress, 1 numeric", false, applyAtW0, 1, false),
		Entry("(positive) egress, 1 numeric", false, applyAtOthers, 1, false),
		// Adding >15 numeric ports requires more than one block.
		Entry("(positive) ingress, 16 numeric", false, applyAtW0, 16, false),
		Entry("(positive) egress, 16 numeric", false, applyAtOthers, 16, false),

		// Negated named port match.  The rule will not match traffic to the named port (so traffic
		// to the named port will fall through to the default deny rule).

		// No numeric ports in the rule, the IP set match will be rendered in the main rule.
		Entry("(negated) ingress, no-numeric", true, applyAtW0, 0, false),
		Entry("(negated) egress, no-numeric", true, applyAtOthers, 0, false),
		// Adding a numeric port changes the way we render iptables rules to use blocks.
		Entry("(negated) ingress, 1 numeric", true, applyAtW0, 1, false),
		Entry("(negated) egress, 1 numeric", true, applyAtOthers, 1, false),
		// Adding >15 numeric ports requires more than one block.
		Entry("(negated) ingress, 16 numeric", true, applyAtW0, 16, false),
		Entry("(negated) egress, 16 numeric", true, applyAtOthers, 16, false),

		// Selection of tests that include a destination selector too.
		Entry("(positive) egress, no-numeric with a dest selector", false, applyAtOthers, 0, true),
		Entry("(positive) egress, 16 numeric with a dest selector", false, applyAtOthers, 16, true),
		Entry("(negated) egress, no-numeric with a dest selector", true, applyAtOthers, 0, true),
		Entry("(negated) egress, 16 numeric with a dest selector", true, applyAtOthers, 16, true),
	)

	Describe("with a policy that combines named ports and selectors", func() {
		var policy *api.Policy
		var oppositeDir, sameDir string
		if testSourcePorts {
			oppositeDir = "destination"
			sameDir = "source"
		} else {
			oppositeDir = "source"
			sameDir = "destination"
		}

		BeforeEach(func() {

			protoTCP := numorstring.ProtocolFromString("tcp")
			policy = api.NewPolicy()
			policy.Metadata.Name = "policy-1"

			entityRule := api.EntityRule{
				Ports: []numorstring.Port{
					numorstring.NamedPort(sharedPortName),
					numorstring.NamedPort(w0PortName),
					numorstring.NamedPort(w1PortName),
					numorstring.SinglePort(4000),
				},
				Selector: fmt.Sprintf("(%s) || (%s) || (%s)",
					w[0].NameSelector(), w[1].NameSelector(), w[2].NameSelector()),
			}

			apiRule := api.Rule{
				Action:   "allow",
				Protocol: &protoTCP,
			}
			if testSourcePorts {
				apiRule.Source = entityRule
			} else {
				apiRule.Destination = entityRule
			}
			policy.Spec.IngressRules = []api.Rule{
				apiRule,
			}
			policy.Spec.Selector = "all()"
		})

		JustBeforeEach(func() {
			createPolicy(policy)
		})

		// This spec establishes a baseline for the connectivity, then the specs below run
		// with tweaked versions of the policy.
		expectBaselineConnectivity := func() {
			cc.ExpectSome(w[0], w[1].Port(sharedPort)) // Allowed by named port in list.
			cc.ExpectSome(w[1], w[0].Port(sharedPort)) // Allowed by named port in list.
			cc.ExpectSome(w[3], w[1].Port(sharedPort)) // Allowed by named port in list.
			cc.ExpectSome(w[3], w[0].Port(sharedPort)) // Allowed by named port in list.
			cc.ExpectSome(w[3], w[2].Port(sharedPort)) // Allowed by named port in list.
			cc.ExpectNone(w[1], w[3].Port(sharedPort)) // Disallowed by positive selector.
			cc.ExpectNone(w[2], w[3].Port(sharedPort)) // Disallowed by positive selector.
			cc.ExpectSome(w[3], w[0].Port(w0Port))     // Allowed by named port in list.
			cc.ExpectSome(w[3], w[1].Port(w1Port))     // Allowed by named port in list.
			cc.ExpectNone(w[3], w[2].Port(w2Port))     // Not in ports list.
			cc.ExpectSome(w[2], w[0].Port(4000))       // Numeric port in list.
			cc.ExpectSome(w[3], w[0].Port(4000))       // Numeric port in list.
			cc.ExpectNone(w[2], w[0].Port(3000))       // Numeric port not in list.

			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
				Equal(cc.ExpectedConnectivity()),
				dumpPolicy(policy),
			)
		}
		It("should have expected connectivity", expectBaselineConnectivity)

		Describe("with a negative "+sameDir+" selector, removing w[2]", func() {
			BeforeEach(func() {
				if testSourcePorts {
					policy.Spec.IngressRules[0].Source.NotSelector = w[2].NameSelector()
				} else {
					policy.Spec.IngressRules[0].Destination.NotSelector = w[2].NameSelector()
				}
			})

			It("should have expected connectivity", func() {
				cc.ExpectSome(w[3], w[1].Port(sharedPort)) // No change.
				cc.ExpectSome(w[3], w[0].Port(sharedPort)) // No change.
				cc.ExpectNone(w[3], w[2].Port(sharedPort)) // Disallowed by negative selector.
				cc.ExpectNone(w[2], w[3].Port(sharedPort)) // No change.
				cc.ExpectSome(w[3], w[0].Port(w0Port))     // No change.
				cc.ExpectSome(w[3], w[1].Port(w1Port))     // No change.
				cc.ExpectNone(w[3], w[2].Port(w2Port))     // No change.
				cc.ExpectSome(w[2], w[0].Port(4000))       // No change.
				cc.ExpectSome(w[3], w[0].Port(4000))       // No change.
				cc.ExpectNone(w[2], w[0].Port(3000))       // No change.

				Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
					Equal(cc.ExpectedConnectivity()),
					dumpPolicy(policy),
				)
			})
		})

		Describe("with only a negative "+sameDir+" selector, removing w[2]", func() {
			BeforeEach(func() {
				if testSourcePorts {
					policy.Spec.IngressRules[0].Source.Selector = ""
					policy.Spec.IngressRules[0].Source.NotSelector = w[2].NameSelector()
				} else {
					policy.Spec.IngressRules[0].Destination.Selector = ""
					policy.Spec.IngressRules[0].Destination.NotSelector = w[2].NameSelector()
				}
			})

			It("should have expected connectivity", func() {
				cc.ExpectSome(w[3], w[1].Port(sharedPort)) // No change.
				cc.ExpectSome(w[3], w[0].Port(sharedPort)) // No change.
				cc.ExpectNone(w[3], w[2].Port(sharedPort)) // Disallowed by negative selector.
				cc.ExpectSome(w[2], w[3].Port(sharedPort)) // Now allowed.
				cc.ExpectSome(w[1], w[3].Port(sharedPort)) // Now allowed.
				cc.ExpectSome(w[3], w[0].Port(w0Port))     // No change.
				cc.ExpectSome(w[3], w[1].Port(w1Port))     // No change.
				cc.ExpectNone(w[3], w[2].Port(w2Port))     // No change.
				cc.ExpectSome(w[2], w[0].Port(4000))       // No change.
				cc.ExpectSome(w[3], w[0].Port(4000))       // No change.
				cc.ExpectNone(w[2], w[0].Port(3000))       // No change.

				Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
					Equal(cc.ExpectedConnectivity()),
					dumpPolicy(policy),
				)
			})
		})

		expectW2AndW3Blocked := func() {
			cc.ExpectSome(w[0], w[1].Port(sharedPort)) // No change
			cc.ExpectSome(w[1], w[0].Port(sharedPort)) // No change

			// Everything blocked from w[2] and w[3].
			cc.ExpectNone(w[3], w[1].Port(sharedPort))
			cc.ExpectNone(w[3], w[2].Port(sharedPort))
			cc.ExpectNone(w[2], w[3].Port(sharedPort))
			cc.ExpectNone(w[3], w[0].Port(w0Port))
			cc.ExpectNone(w[3], w[2].Port(w2Port))
			cc.ExpectNone(w[2], w[0].Port(4000))
			cc.ExpectNone(w[2], w[0].Port(3000))

			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
				Equal(cc.ExpectedConnectivity()),
				dumpPolicy(policy),
			)
		}

		Describe("with "+oppositeDir+" selectors, removing w[2] and w[3]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					Selector: fmt.Sprintf("(%s) || (%s) || (%s)",
						w[0].NameSelector(), w[1].NameSelector(), w[2].NameSelector()),
					NotSelector: w[2].NameSelector(),
				}
				if testSourcePorts {
					policy.Spec.IngressRules[0].Destination = rule
				} else {
					policy.Spec.IngressRules[0].Source = rule
				}
			})

			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with "+oppositeDir+" CIDRs, allowing only w[0] and w[1]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					Nets: []*net.IPNet{
						w[0].IPNet(),
						w[1].IPNet(),
					},
				}
				if testSourcePorts {
					policy.Spec.IngressRules[0].Destination = rule
				} else {
					policy.Spec.IngressRules[0].Source = rule
				}
			})

			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with negated "+oppositeDir+" CIDRs, allowing only w[0] and w[1]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					NotNets: []*net.IPNet{
						w[2].IPNet(),
						w[3].IPNet(),
					},
				}
				if testSourcePorts {
					policy.Spec.IngressRules[0].Destination = rule
				} else {
					policy.Spec.IngressRules[0].Source = rule
				}
			})

			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with positive and negative "+oppositeDir+" CIDRs, allowing only w[0] and w[1]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					Nets: []*net.IPNet{
						w[0].IPNet(),
						w[1].IPNet(),
						w[2].IPNet(), // Allowed here but excluded below.
					},
					NotNets: []*net.IPNet{
						w[2].IPNet(),
					},
				}
				if testSourcePorts {
					policy.Spec.IngressRules[0].Destination = rule
				} else {
					policy.Spec.IngressRules[0].Source = rule
				}
			})
			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with all positive CIDRs replacing the selector", func() {
			BeforeEach(func() {
				nets := []*net.IPNet{
					w[0].IPNet(),
					w[1].IPNet(),
					w[2].IPNet(),
				}
				if testSourcePorts {
					policy.Spec.IngressRules[0].Source.Selector = ""
					policy.Spec.IngressRules[0].Source.Nets = nets
				} else {
					policy.Spec.IngressRules[0].Destination.Selector = ""
					policy.Spec.IngressRules[0].Destination.Nets = nets
				}
			})

			It("should have expected connectivity", expectBaselineConnectivity)

			Describe("with negative destination nets blocking w[2] and w[3]", func() {
				BeforeEach(func() {
					nets := []*net.IPNet{
						w[2].IPNet(),
						w[3].IPNet(),
					}
					if testSourcePorts {
						policy.Spec.IngressRules[0].Source.NotNets = nets
					} else {
						policy.Spec.IngressRules[0].Destination.NotNets = nets
					}
				})

				It("should give expected connectivity", func() {
					cc.ExpectSome(w[0], w[1].Port(sharedPort)) // No change.
					cc.ExpectSome(w[1], w[0].Port(sharedPort)) // No change.
					cc.ExpectSome(w[3], w[1].Port(sharedPort)) // No change.
					cc.ExpectSome(w[3], w[0].Port(sharedPort)) // No change.
					cc.ExpectNone(w[3], w[2].Port(sharedPort)) // Blocked by NotNets.
					cc.ExpectNone(w[1], w[3].Port(sharedPort)) // Blocked by w[3] not being in Nets.
					cc.ExpectNone(w[2], w[3].Port(sharedPort)) // Blocked by w[3] not being in Nets.
					cc.ExpectSome(w[3], w[0].Port(w0Port))     // No change.
					cc.ExpectSome(w[3], w[1].Port(w1Port))     // No change.
					cc.ExpectNone(w[3], w[2].Port(w2Port))     // Blocked by NotNets.
					cc.ExpectSome(w[2], w[0].Port(4000))       // No change.
					cc.ExpectSome(w[3], w[0].Port(4000))       // No change.
					cc.ExpectNone(w[2], w[0].Port(3000))       // No change.

					Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
						Equal(cc.ExpectedConnectivity()),
						dumpPolicy(policy),
					)
				})
			})
		})

		Describe("with negated ports conflicting with positive ports", func() {
			BeforeEach(func() {
				ports := []numorstring.Port{
					numorstring.NamedPort(w0PortName),
					numorstring.SinglePort(w1Port),
					numorstring.SinglePort(4000),
				}
				if testSourcePorts {
					policy.Spec.IngressRules[0].Source.NotPorts = ports
				} else {
					policy.Spec.IngressRules[0].Destination.NotPorts = ports
				}
			})

			It("should have expected connectivity", func() {
				cc.ExpectSome(w[3], w[1].Port(sharedPort)) // No change
				cc.ExpectSome(w[3], w[0].Port(sharedPort)) // No change
				cc.ExpectNone(w[2], w[3].Port(sharedPort)) // No change
				cc.ExpectSome(w[3], w[2].Port(sharedPort)) // No change
				cc.ExpectNone(w[3], w[0].Port(w0Port))     // Disallowed by named port in NotPorts list.
				cc.ExpectNone(w[3], w[1].Port(w1Port))     // Disallowed by numeric port in NotPorts list.
				cc.ExpectNone(w[3], w[2].Port(w2Port))     // No change
				cc.ExpectNone(w[2], w[0].Port(4000))       // Numeric port in NotPorts list.
				cc.ExpectNone(w[3], w[0].Port(4000))       // Numeric port in NotPorts list.
				cc.ExpectNone(w[2], w[0].Port(3000))       // No change

				Eventually(cc.ActualConnectivity, "10s", "100ms").Should(
					Equal(cc.ExpectedConnectivity()),
					dumpPolicy(policy),
				)
			})
		})
	})
}

// TODO UDP
// TODO Corner case: UDP named port with TCP match

func dumpPolicy(pol *api.Policy) string {
	jsonPol, _ := json.MarshalIndent(pol, "\t", "  ")
	polDump := fmt.Sprintf("Active policy:\n\tMetadata: %+v\n\tSpec: %+v\n\tJSON:\n\t%s",
		pol.Metadata, pol.Spec, string(jsonPol))
	return polDump
}
