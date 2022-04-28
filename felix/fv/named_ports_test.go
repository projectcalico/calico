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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	libv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Context("_BPF-SAFE_ TCP: Destination named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(false, "tcp")
})
var _ = Context("_BPF-SAFE_ TCP: Source named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(true, "tcp")
})

var _ = Context("_BPF-SAFE_ UDP: Destination named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(false, "udp")
})
var _ = Context("_BPF-SAFE_ UDP: Source named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(true, "udp")
})

var _ = Context("SCTP: Destination named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(false, "sctp")
})
var _ = Context("SCTP: Source named ports: with initialized Felix, etcd datastore, 3 workloads, allow-all profile", func() {
	describeNamedPortTests(true, "sctp")
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
func describeNamedPortTests(testSourcePorts bool, protocol string) {

	var (
		etcd   *containers.Container
		felix  *infrastructure.Felix
		client client.Interface
		infra  infrastructure.DatastoreInfra
		w      [4]*workload.Workload
		cc     *connectivity.Checker
	)

	const (
		sharedPortName       = "shared-port"
		w0PortName           = "w0-port"
		w1PortName           = "w1-port"
		sharedPort           = 1100
		w0Port               = 1000
		w1Port               = 1001
		w2Port               = 1002
		sourceTestTargetPort = "10000"
	)

	BeforeEach(func() {
		felix, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(infrastructure.DefaultTopologyOptions())
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")
		// Create some workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			workloadPort := uint16(1000 + ii)

			var ports string
			if testSourcePorts {
				ports = sourceTestTargetPort
			} else {
				ports = fmt.Sprintf("3000,4000,%d,%d", sharedPort, workloadPort)
			}
			w[ii] = workload.Run(
				felix,
				"w"+iiStr,
				"default",
				"10.65.0.1"+iiStr,
				ports,
				protocol,
			)

			// Includes some named ports on each workload.  Each workload gets its own named port,
			// which is unique and a shared one.
			w[ii].WorkloadEndpoint.Spec.Ports = []libv3.WorkloadEndpointPort{
				{
					Port:     sharedPort,
					Name:     sharedPortName,
					Protocol: numorstring.ProtocolFromString(protocol),
				},
				{
					Port:     workloadPort,
					Name:     fmt.Sprintf("w%d-port", ii),
					Protocol: numorstring.ProtocolFromString(protocol),
				},
				{
					Port:     2200,
					Name:     "shared-udp",
					Protocol: numorstring.ProtocolFromString("udp"),
				},
			}
			w[ii].DefaultPort = sourceTestTargetPort
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{
			ReverseDirection: testSourcePorts,
			Protocol:         protocol,
		}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			log.Warn("Test failed, dumping diags...")
			utils.Run("docker", "logs", felix.Name)
			utils.Run("docker", "exec", felix.Name, "iptables-save", "-c")
			utils.Run("docker", "exec", felix.Name, "ipset", "list")
			utils.Run("docker", "exec", felix.Name, "ip", "r")

			profiles, err := client.Profiles().List(context.Background(), options.ListOptions{})
			if err == nil {
				log.Info("DIAGS: Calico Profiles:")
				for _, profile := range profiles.Items {
					log.Info(profile)
				}
			}
			policies, err := client.NetworkPolicies().List(context.Background(), options.ListOptions{})
			if err == nil {
				log.Info("DIAGS: Calico NetworkPolicies:")
				for _, policy := range policies.Items {
					log.Info(policy)
				}
			}
			gnps, err := client.GlobalNetworkPolicies().List(context.Background(), options.ListOptions{})
			if err == nil {
				log.Info("DIAGS: Calico GlobalNetworkPolicies:")
				for _, gnp := range gnps.Items {
					log.Info(gnp)
				}
			}
			workloads, err := client.WorkloadEndpoints().List(context.Background(), options.ListOptions{})
			if err == nil {
				log.Info("DIAGS: Calico WorkloadEndpoints:")
				for _, w := range workloads.Items {
					log.Info(w)
				}
			}
			nodes, err := client.Nodes().List(context.Background(), options.ListOptions{})
			if err == nil {
				log.Info("DIAGS: Calico Nodes:")
				for _, n := range nodes.Items {
					log.Info(n)
				}
			}

			felix.Exec("calico-bpf", "ipsets", "dump")
			felix.Exec("bpftool", "map")
			felix.Exec("bpftool", "prog")
		}

		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentSpecReport().Failed() {
			utils.Run("docker", "exec", etcd.Name, "etcdctl", "get", "/", "--prefix", "--keys-only")
		}
		etcd.Stop()
		infra.Stop()
	})

	type ingressEgress int
	const (
		applyAtW0 ingressEgress = iota
		applyAtOthers
	)

	bpfEnabled := false
	if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
		bpfEnabled = true
	}

	cleanConntrack := func() {
		if bpfEnabled && protocol == "udp" {
			felix.Exec("calico-bpf", "conntrack", "clean")
		}
	}

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

			cc.CheckConnectivity(connectivity.CheckWithBeforeRetry(cleanConntrack))
		})
	})

	createPolicy := func(policy *api.NetworkPolicy) {
		log.WithField("policy", dumpResource(policy)).Info("Creating policy")
		_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
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
			pol := api.NewNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "policy-1"
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
			protoStruct := numorstring.ProtocolFromString(protocol)
			apiRule := api.Rule{
				Action:   api.Allow,
				Protocol: &protoStruct,
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
					pol.Spec.Egress = rules
				} else {
					pol.Spec.Ingress = rules
				}
			} else {
				pol.Spec.Selector = fmt.Sprintf("!(%s)", w[0].NameSelector())
				if testSourcePorts {
					pol.Spec.Ingress = rules
				} else {
					pol.Spec.Egress = rules
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

			cc.CheckConnectivity(dumpResource(pol), connectivity.CheckWithBeforeRetry(cleanConntrack))
		},

		// Non-negated named port match.  The rule will allow traffic to the named port.

		// No numeric ports in the rule, the IP set match will be rendered in the main rule.
		Entry("(positive) ingress, no-numeric _CANARY_", false, applyAtW0, 0, false),
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
		var policy *api.NetworkPolicy
		var oppositeDir, sameDir string
		if testSourcePorts {
			oppositeDir = "destination"
			sameDir = "source"
		} else {
			oppositeDir = "source"
			sameDir = "destination"
		}

		BeforeEach(func() {
			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"

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

			protoStruct := numorstring.ProtocolFromString(protocol)
			apiRule := api.Rule{
				Action:   api.Allow,
				Protocol: &protoStruct,
			}
			if testSourcePorts {
				apiRule.Source = entityRule
			} else {
				apiRule.Destination = entityRule
			}
			policy.Spec.Ingress = []api.Rule{
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

			cc.CheckConnectivity(dumpResource(policy), connectivity.CheckWithBeforeRetry(cleanConntrack))
		}
		It("should have expected connectivity", expectBaselineConnectivity)

		Describe("with a negative "+sameDir+" selector, removing w[2]", func() {
			BeforeEach(func() {
				if testSourcePorts {
					policy.Spec.Ingress[0].Source.NotSelector = w[2].NameSelector()
				} else {
					policy.Spec.Ingress[0].Destination.NotSelector = w[2].NameSelector()
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

				cc.CheckConnectivity(dumpResource(policy), connectivity.CheckWithBeforeRetry(cleanConntrack))
			})
		})

		Describe("with only a negative "+sameDir+" selector, removing w[2]", func() {
			BeforeEach(func() {
				if testSourcePorts {
					policy.Spec.Ingress[0].Source.Selector = ""
					policy.Spec.Ingress[0].Source.NotSelector = w[2].NameSelector()
				} else {
					policy.Spec.Ingress[0].Destination.Selector = ""
					policy.Spec.Ingress[0].Destination.NotSelector = w[2].NameSelector()
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

				cc.CheckConnectivity(dumpResource(policy), connectivity.CheckWithBeforeRetry(cleanConntrack))
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

			cc.CheckConnectivity(dumpResource(policy), connectivity.CheckWithBeforeRetry(cleanConntrack))
		}

		Describe("with "+oppositeDir+" selectors, removing w[2] and w[3]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					Selector: fmt.Sprintf("(%s) || (%s) || (%s)",
						w[0].NameSelector(), w[1].NameSelector(), w[2].NameSelector()),
					NotSelector: w[2].NameSelector(),
				}
				if testSourcePorts {
					policy.Spec.Ingress[0].Destination = rule
				} else {
					policy.Spec.Ingress[0].Source = rule
				}
			})

			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with "+oppositeDir+" CIDRs, allowing only w[0] and w[1]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					Nets: []string{
						w[0].IPNet(),
						w[1].IPNet(),
					},
				}
				if testSourcePorts {
					policy.Spec.Ingress[0].Destination = rule
				} else {
					policy.Spec.Ingress[0].Source = rule
				}
			})

			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with negated "+oppositeDir+" CIDRs, allowing only w[0] and w[1]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					NotNets: []string{
						w[2].IPNet(),
						w[3].IPNet(),
					},
				}
				if testSourcePorts {
					policy.Spec.Ingress[0].Destination = rule
				} else {
					policy.Spec.Ingress[0].Source = rule
				}
			})

			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with positive and negative "+oppositeDir+" CIDRs, allowing only w[0] and w[1]", func() {
			BeforeEach(func() {
				rule := api.EntityRule{
					Nets: []string{
						w[0].IPNet(),
						w[1].IPNet(),
						w[2].IPNet(), // Allowed here but excluded below.
					},
					NotNets: []string{
						w[2].IPNet(),
					},
				}
				if testSourcePorts {
					policy.Spec.Ingress[0].Destination = rule
				} else {
					policy.Spec.Ingress[0].Source = rule
				}
			})
			It("should have expected connectivity", expectW2AndW3Blocked)
		})

		Describe("with all positive CIDRs replacing the selector", func() {
			BeforeEach(func() {
				nets := []string{
					w[0].IPNet(),
					w[1].IPNet(),
					w[2].IPNet(),
				}
				if testSourcePorts {
					policy.Spec.Ingress[0].Source.Selector = ""
					policy.Spec.Ingress[0].Source.Nets = nets
				} else {
					policy.Spec.Ingress[0].Destination.Selector = ""
					policy.Spec.Ingress[0].Destination.Nets = nets
				}
			})

			It("should have expected connectivity", expectBaselineConnectivity)

			Describe("with negative destination nets blocking w[2] and w[3]", func() {
				BeforeEach(func() {
					nets := []string{
						w[2].IPNet(),
						w[3].IPNet(),
					}
					if testSourcePorts {
						policy.Spec.Ingress[0].Source.NotNets = nets
					} else {
						policy.Spec.Ingress[0].Destination.NotNets = nets
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

					cc.CheckConnectivity(dumpResource(policy), connectivity.CheckWithBeforeRetry(cleanConntrack))
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
					policy.Spec.Ingress[0].Source.NotPorts = ports
				} else {
					policy.Spec.Ingress[0].Destination.NotPorts = ports
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

				cc.CheckConnectivity(dumpResource(policy), connectivity.CheckWithBeforeRetry(cleanConntrack))
			})
		})
	})
}

// This test reproduces a particular Kubernetes failure scenario seen during FV testing named ports.
var _ = Describe("TCP: named port with a simulated kubernetes nginx and client", func() {
	var (
		etcd              *containers.Container
		felix             *infrastructure.Felix
		client            client.Interface
		infra             infrastructure.DatastoreInfra
		nginx             *workload.Workload
		nginxClient       *workload.Workload
		defaultDenyPolicy *api.NetworkPolicy
		allowHTTPPolicy   *api.NetworkPolicy
		cc                *connectivity.Checker
	)

	BeforeEach(func() {
		felix, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(infrastructure.DefaultTopologyOptions())
		// Create a namespace profile and write to the datastore.
		infrastructure.CreateDefaultProfile(client, "kns.test", map[string]string{"name": "test"}, "")
		// Create nginx workload.
		nginx = workload.Run(
			felix,
			"nginx",
			"kns.test",
			"10.65.0.1",
			"80,81",
			"tcp",
		)
		nginx.WorkloadEndpoint.Labels = map[string]string{
			"name": "nginx",
		}
		nginx.WorkloadEndpoint.Spec.Ports = []libv3.WorkloadEndpointPort{
			{
				Port:     80,
				Name:     "http-port",
				Protocol: numorstring.ProtocolFromString("tcp"),
			},
		}
		nginx.WorkloadEndpoint.Spec.Profiles = []string{"kns.test"}
		nginx.DefaultPort = "80"
		nginx.Configure(client)

		// Create client workload.
		nginxClient = workload.Run(
			felix,
			"client",
			"kns.test",
			"10.65.0.2",
			"1000",
			"tcp",
		)
		nginxClient.WorkloadEndpoint.Spec.Profiles = []string{"kns.test"}
		nginxClient.Configure(client)

		// Create a default deny policy (but we don't actually write it to the datastore yet).
		defaultDenyPolicy = api.NewNetworkPolicy()
		defaultDenyPolicy.Namespace = "fv"
		defaultDenyPolicy.Name = "knp.default.default-deny"
		thousand := 1000.0
		defaultDenyPolicy.Spec.Order = &thousand
		defaultDenyPolicy.Spec.Selector = "name == 'nginx'"
		defaultDenyPolicy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}

		// Create a policy that opens up the HTTP named port (but we don't actually write it to the
		// datastore yet).
		allowHTTPPolicy = api.NewNetworkPolicy()
		allowHTTPPolicy.Namespace = "fv"
		allowHTTPPolicy.Name = "knp.default.access-nginx"
		protoStruct := numorstring.ProtocolFromString("tcp")
		apiRule := api.Rule{
			Action:   api.Allow,
			Protocol: &protoStruct,
			Destination: api.EntityRule{
				Ports: []numorstring.Port{
					numorstring.NamedPort("http-port"),
				},
			},
		}
		allowHTTPPolicy.Spec.Ingress = []api.Rule{
			apiRule,
		}
		allowHTTPPolicy.Spec.Order = &thousand
		allowHTTPPolicy.Spec.Selector = "name == 'nginx'"
		allowHTTPPolicy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			log.Warn("Test failed, dumping diags...")
			utils.Run("docker", "logs", felix.Name)
			utils.Run("docker", "exec", felix.Name, "iptables-save", "-c")
			utils.Run("docker", "exec", felix.Name, "ipset", "list")
			utils.Run("docker", "exec", felix.Name, "ip", "r")
		}

		nginx.Stop()
		nginxClient.Stop()
		felix.Stop()

		if CurrentSpecReport().Failed() {
			utils.Run("docker", "exec", etcd.Name, "etcdctl", "get", "/", "--prefix", "--keys-only")
		}
		etcd.Stop()
		infra.Stop()
	})

	It("HTTP port policy should open up nginx port", func() {
		// The profile has a default allow so we should start with connectivity.
		cc.ExpectSome(nginxClient, nginx.Port(80))
		cc.ExpectSome(nginxClient, nginx.Port(81))
		cc.CheckConnectivity()

		// Then we add an (ingress) default deny policy, which should cut it off again.
		// It's important to check this before applying the allow policy to check that the correct
		// policy is opening up the port.
		_, err := client.NetworkPolicies().Create(utils.Ctx, defaultDenyPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		cc.ResetExpectations()
		cc.ExpectNone(nginxClient, nginx.Port(80))
		cc.ExpectNone(nginxClient, nginx.Port(81))
		cc.CheckConnectivity()

		_, err = client.NetworkPolicies().Create(utils.Ctx, allowHTTPPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		cc.ResetExpectations()
		cc.ExpectSome(nginxClient, nginx.Port(80))
		cc.ExpectNone(nginxClient, nginx.Port(81))
		cc.CheckConnectivity()
	})
})

// describeNamedPortHostEndpointTests describes tests for named ports with
// hostendpoints. If namedHostEndpoint is true, a named hostendpoint using eth0
// is created for each felix. Otherwise, an all-interfaces host endpoint is
// created for the felixes.
func describeNamedPortHostEndpointTests(getInfra infrastructure.InfraFactory, namedHostEndpoint bool) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
		hostW   [2]*workload.Workload
		cc      *connectivity.Checker
	)

	tcp := numorstring.ProtocolFromString("TCP")

	BeforeEach(func() {
		infra = getInfra()

		felixes, client = infrastructure.StartNNodeTopology(2, infrastructure.DefaultTopologyOptions(), infra)

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())

		// Start a host-networked workload on each host so we have something to connect to.
		for ii, felix := range felixes {
			hostW[ii] = workload.Run(
				felixes[ii],
				fmt.Sprintf("host%d", ii),
				"",
				felixes[ii].IP,
				"8055,8056",
				"tcp")

			hostEp := api.NewHostEndpoint()
			hostEp.Name = fmt.Sprintf("host-endpoint-%d", ii)
			hostEp.Labels = map[string]string{
				"host-endpoint": "true",
				"host":          fmt.Sprint(ii),
			}
			hostEp.Spec.Node = felix.Hostname

			if namedHostEndpoint {
				hostEp.Spec.InterfaceName = "eth0"
			} else {
				hostEp.Spec.InterfaceName = "*"
			}

			hostEp.Spec.ExpectedIPs = []string{felix.IP}
			hostEp.Spec.Ports = []api.EndpointPort{
				{
					Name:     "http",
					Protocol: tcp,
					Port:     8055,
				},
			}
			_, err = client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		cc = &connectivity.Checker{}
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

		for _, wl := range hostW {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		infra.Stop()
	})

	expectNoConnectivity := func() {
		cc.ExpectNone(felixes[0], hostW[1].Port(8055))
		cc.ExpectNone(felixes[1], hostW[0].Port(8055))
		cc.ExpectNone(felixes[0], hostW[1].Port(8056))
		cc.ExpectNone(felixes[1], hostW[0].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectNamedPortOpen := func() {
		cc.ExpectSome(felixes[0], hostW[1].Port(8055))
		cc.ExpectSome(felixes[1], hostW[0].Port(8055))
		cc.ExpectNone(felixes[0], hostW[1].Port(8056))
		cc.ExpectNone(felixes[1], hostW[0].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	It("should have expected initial connectivity", func() {
		expectNoConnectivity()
	})

	It("should have expected connectivity with named port policies", func() {
		pol := api.NewGlobalNetworkPolicy()
		pol.Name = "test-policy"
		pol.Spec.Selector = "host == '1' || host == '0'"
		pol.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		pol.Spec.Egress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &tcp,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("http")},
				},
			},
		}
		pol, err := client.GlobalNetworkPolicies().Create(utils.Ctx, pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		expectNoConnectivity()

		pol2 := api.NewGlobalNetworkPolicy()
		pol2.Name = "test-policy-2"
		pol2.Spec.Selector = "host == '1' || host == '0'"
		pol2.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		pol2.Spec.Ingress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &tcp,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("http")},
				},
			},
		}
		pol2, err = client.GlobalNetworkPolicies().Create(utils.Ctx, pol2, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectNamedPortOpen()

		// Switch to incorrect numeric port, should fail.
		pol.Spec.Egress[0].Destination.Ports[0] = numorstring.SinglePort(80)
		pol, err = client.GlobalNetworkPolicies().Update(utils.Ctx, pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectNoConnectivity()

		// Switch to correct numeric port, should work.
		pol.Spec.Egress[0].Destination.Ports[0] = numorstring.SinglePort(8055)
		pol, err = client.GlobalNetworkPolicies().Update(utils.Ctx, pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectNamedPortOpen()

		// Switch to incorrect named port, should fail.
		pol.Spec.Egress[0].Destination.Ports[0] = numorstring.NamedPort("wrong")
		pol, err = client.GlobalNetworkPolicies().Update(utils.Ctx, pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectNoConnectivity()

		// Switch to correct named port, should work.
		pol.Spec.Egress[0].Destination.Ports[0] = numorstring.NamedPort("http")
		pol, err = client.GlobalNetworkPolicies().Update(utils.Ctx, pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectNamedPortOpen()
	})
}

var _ = infrastructure.DatastoreDescribe("named port, named host endpoint",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		describeNamedPortHostEndpointTests(getInfra, true)
	})

var _ = infrastructure.DatastoreDescribe("named port, all-interfaces host endpoint",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		describeNamedPortHostEndpointTests(getInfra, false)
	})

// This test verifies that TCP named ports aren't matched by UDP rules and vice versa.
var _ = Describe("tests with mixed TCP/UDP", func() {
	var (
		etcd                        *containers.Container
		felix                       *infrastructure.Felix
		client                      client.Interface
		infra                       infrastructure.DatastoreInfra
		targetTCPWorkload           *workload.Workload
		targetUDPWorkload           *workload.Workload
		clientWorkload              *workload.Workload
		allowConfusedProtocolPolicy *api.NetworkPolicy
		udpCC                       *connectivity.Checker
		tcpCC                       *connectivity.Checker
	)

	BeforeEach(func() {
		felix, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(infrastructure.DefaultTopologyOptions())
		infrastructure.CreateDefaultProfile(client, "open", map[string]string{"default": ""}, "")

		createTarget := func(ip, protocol string) *workload.Workload {
			// Create target workloads.
			w := workload.Run(
				felix,
				"target-"+protocol,
				"open",
				ip,
				"80,81",
				protocol,
			)
			w.WorkloadEndpoint.Labels = map[string]string{
				"name": "nginx",
			}
			w.WorkloadEndpoint.Spec.Ports = []libv3.WorkloadEndpointPort{
				{
					Port:     80,
					Name:     "tcp-port",
					Protocol: numorstring.ProtocolFromString("tcp"),
				},
				{
					Port:     81,
					Name:     "udp-port",
					Protocol: numorstring.ProtocolFromString("udp"),
				},
			}
			w.WorkloadEndpoint.Spec.Profiles = []string{"open"}
			w.Configure(client)
			return w
		}

		targetTCPWorkload = createTarget("10.65.0.2", "tcp")
		targetUDPWorkload = createTarget("10.65.0.3", "udp")

		// Create client workload.
		clientWorkload = workload.Run(
			felix,
			"client",
			"open",
			"10.65.0.1",
			"1000",
			"tcp", // Note: protocol isn't relevant for client.
		)
		clientWorkload.WorkloadEndpoint.Spec.Profiles = []string{"open"}
		clientWorkload.Configure(client)

		// Create a policy that tries to open up the TCP named port over UDP and vice/versa.
		allowConfusedProtocolPolicy = api.NewNetworkPolicy()
		allowConfusedProtocolPolicy.Namespace = "fv"
		allowConfusedProtocolPolicy.Name = "knp.default.confused"
		protoUDPStruct := numorstring.ProtocolFromString("udp")
		protoTCPStruct := numorstring.ProtocolFromString("tcp")
		allowConfusedProtocolPolicy.Spec.Ingress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &protoTCPStruct,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{
						numorstring.NamedPort("udp-port"),
					},
				},
			},
			{
				Action:   api.Allow,
				Protocol: &protoUDPStruct,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{
						numorstring.NamedPort("http-port"),
					},
				},
			},
		}
		allowConfusedProtocolPolicy.Spec.Selector = "name == 'nginx'"
		allowConfusedProtocolPolicy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}

		udpCC = &connectivity.Checker{Protocol: "udp"}
		tcpCC = &connectivity.Checker{Protocol: "tcp"}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			log.Warn("Test failed, dumping diags...")
			utils.Run("docker", "logs", felix.Name)
			utils.Run("docker", "exec", felix.Name, "iptables-save", "-c")
			utils.Run("docker", "exec", felix.Name, "ipset", "list")
			utils.Run("docker", "exec", felix.Name, "ip", "r")
		}

		targetTCPWorkload.Stop()
		targetUDPWorkload.Stop()
		clientWorkload.Stop()
		felix.Stop()

		if CurrentSpecReport().Failed() {
			utils.Run("docker", "exec", etcd.Name, "etcdctl", "get", "/", "--prefix", "--keys-only")
		}
		etcd.Stop()
		infra.Stop()
	})

	It("shouldn't confuse TCP and UDP ports", func() {
		// The profile has a default allow so we should start with connectivity.
		tcpCC.ExpectSome(clientWorkload, targetTCPWorkload.Port(80))
		tcpCC.ExpectSome(clientWorkload, targetTCPWorkload.Port(81))
		tcpCC.CheckConnectivity()

		udpCC.ExpectSome(clientWorkload, targetUDPWorkload.Port(80))
		udpCC.ExpectSome(clientWorkload, targetUDPWorkload.Port(81))
		udpCC.CheckConnectivity()

		// Then the connectivity should be broken by adding the confused policy.
		_, err := client.NetworkPolicies().Create(utils.Ctx, allowConfusedProtocolPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		tcpCC.ResetExpectations()
		tcpCC.ExpectNone(clientWorkload, targetTCPWorkload.Port(80))
		tcpCC.ExpectNone(clientWorkload, targetTCPWorkload.Port(81))
		tcpCC.CheckConnectivity()
		udpCC.ResetExpectations()
		udpCC.ExpectNone(clientWorkload, targetUDPWorkload.Port(80))
		udpCC.ExpectNone(clientWorkload, targetUDPWorkload.Port(81))
		udpCC.CheckConnectivity()
	})
})

func dumpResource(pol interface {
	GetName() string
}) string {
	jsonPol, _ := json.MarshalIndent(pol, "\t", "  ")
	polDump := fmt.Sprintf("Active policy:\n\tName: %+v\n\tObject: %+v\n\tJSON:\n\t%s",
		pol.GetName(), pol, string(jsonPol))
	return polDump
}
