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
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/workload"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	numPolicies    = 20
	numNetworkSets = 100
)

// netsetsConfig is used to parametrise the whole suite of tests for IPv4 or IPv6, it provides
// methods that return:
//
//     - the IP to use for a given workload, each from a separate subnet
//     - a CIDR that encompasses each workload's IP (and only its IP)
//     - a full-length CIDR (i.e. the IP address expressed as a /32 or /128).
type netsetsConfig struct {
	ipVersion int
	zeroCIDR  string
}

func (c netsetsConfig) workloadIP(workloadIdx int, namespaced bool) string {
	if c.ipVersion == 4 {
		if namespaced {
			// Each IP is in its own /24.
			return fmt.Sprintf("10.64.%d.1", workloadIdx)
		}
		return fmt.Sprintf("10.65.%d.1", workloadIdx)
	}
	if namespaced {
		// Each IP gets its own /64.
		return fmt.Sprintf("fdc6:3dbc:e983:cbc%x::1", workloadIdx)
	}

	return fmt.Sprintf("fdc6:3dbc:e983:cdc%x::100", workloadIdx)
}

func (c netsetsConfig) workloadCIDR(workloadIdx, prefixLengthDelta int, namespaced bool) string {
	if c.ipVersion == 4 {
		if namespaced {
			return fmt.Sprintf("10.64.%d.0/%d", workloadIdx, 24+prefixLengthDelta)
		}
		return fmt.Sprintf("10.65.%d.0/%d", workloadIdx, 24+prefixLengthDelta)
	}
	if namespaced {
		return fmt.Sprintf("fdc6:3dbc:e983:cbc%x::/%d", workloadIdx, 64+prefixLengthDelta)
	}
	return fmt.Sprintf("fdc6:3dbc:e983:cdc%x::/%d", workloadIdx, 64+prefixLengthDelta)
}

func (c netsetsConfig) workloadFullLengthCIDR(workloadIdx int, namespaced bool) string {
	addr := c.workloadIP(workloadIdx, namespaced)
	if c.ipVersion == 4 {
		return addr + "/32"
	}
	return addr + "/128"
}

var _ = Context("_NET_SETS_ Network sets tests with initialized Felix and etcd datastore", func() {

	var (
		etcd     *containers.Container
		felix    *infrastructure.Felix
		felixPID int
		client   client.Interface
		infra    infrastructure.DatastoreInfra
	)

	BeforeEach(func() {
		topologyOptions := infrastructure.DefaultTopologyOptions()
		felix, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(topologyOptions)
		felixPID = felix.GetFelixPID()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			felix.Exec("iptables-save", "-c")
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "get", "/", "--prefix", "--keys-only")
		}
		etcd.Stop()
		infra.Stop()
	})

	describeConnTests := func(c netsetsConfig) {
		var (
			w, nw [4]*workload.Workload
			cc    *connectivity.Checker
			pol   *api.GlobalNetworkPolicy
		)

		createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Creating policy")
			policy, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}

		updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Updating policy")
			policy, err := client.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}

		BeforeEach(func() {
			for ii := range w {
				iiStr := strconv.Itoa(ii)
				var ports string

				ports = "3000"
				w[ii] = workload.Run(
					felix,
					"w"+iiStr,
					"fv",
					c.workloadIP(ii, false),
					ports,
					"tcp",
				)

				w[ii].DefaultPort = "3000"
				w[ii].Configure(client)

				nw[ii] = workload.Run(
					felix,
					"nw"+iiStr,
					"fv",
					c.workloadIP(ii, true),
					ports,
					"tcp",
				)

				nw[ii].DefaultPort = "3000"
				nw[ii].Configure(client)
			}

			cc = &connectivity.Checker{
				Protocol: "tcp",
			}

			pol = api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "policy-1"
			pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Selector: "has(allow-as-source)",
					},
					Destination: api.EntityRule{
						Selector: "has(allow-as-dest)",
					},
				},
			}
			pol.Spec.Egress = []api.Rule{
				{
					Action: "Allow",
				},
			}
			pol.Spec.Selector = "all()"

			pol = createPolicy(pol)
		})

		assertNoConnectivity := func() {
			for i := 0; i < len(w); i++ {
				for j := 0; j < len(w); j++ {
					if i != j {
						cc.ExpectNone(w[i], w[j])
						cc.ExpectNone(nw[i], nw[j])
					}
				}
			}
			cc.CheckConnectivity()
		}

		It("with no matching network sets, should deny all", assertNoConnectivity)

		Describe("with namespaced network sets matching some workloads", func() {
			var (
				namespacedSrcNS  *api.NetworkSet
				namespacedDestNS *api.NetworkSet
			)

			BeforeEach(func() {
				// We put workloads 0, 1 and 2 in a set that's allowed as a source.
				namespacedSrcNS = api.NewNetworkSet()
				namespacedSrcNS.Name = "ns-1"
				namespacedSrcNS.Namespace = "default"
				namespacedSrcNS.Spec.Nets = []string{
					c.workloadCIDR(0, 0, true),
					c.workloadCIDR(1, 0, true),
					c.workloadCIDR(2, 0, true),
				}
				namespacedSrcNS.Labels = map[string]string{
					"allow-as-source": "",
				}
				var err error
				namespacedSrcNS, err = client.NetworkSets().Create(utils.Ctx, namespacedSrcNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				// We put workloads 2 and 3 in a set that's allowed as destination.
				namespacedDestNS = api.NewNetworkSet()
				namespacedDestNS.Name = "ns-2"
				namespacedDestNS.Namespace = "default"
				namespacedDestNS.Spec.Nets = []string{
					c.workloadCIDR(2, 0, true),
					c.workloadCIDR(3, 0, true),
				}
				namespacedDestNS.Labels = map[string]string{
					"allow-as-dest": "",
				}
				namespacedDestNS, err = client.NetworkSets().Create(utils.Ctx, namespacedDestNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			assertBaselineNetsetsConnectivity := func() {
				cc.ExpectNone(nw[0], nw[1]) // not in dest net set
				cc.ExpectSome(nw[0], nw[2])
				cc.ExpectSome(nw[0], nw[3])
				cc.ExpectNone(nw[1], nw[0]) // not in dest net set
				cc.ExpectSome(nw[1], nw[2])
				cc.ExpectSome(nw[1], nw[3])
				cc.ExpectNone(nw[2], nw[0]) // not in dest net set
				cc.ExpectNone(nw[2], nw[1]) // not in dest net set
				cc.ExpectSome(nw[2], nw[3])
				// 3 isn't in the source net set so it can't talk to anyone.
				cc.ExpectNone(nw[3], nw[0])
				cc.ExpectNone(nw[3], nw[1])
				cc.ExpectNone(nw[3], nw[2])
				cc.CheckConnectivity()
			}

			It("should have expected connectivity", assertBaselineNetsetsConnectivity)

			resetNetsetsMembers := func() {
				namespacedSrcNS.Spec.Nets = []string{
					c.workloadCIDR(0, 0, true),
					c.workloadCIDR(1, 0, true),
					c.workloadCIDR(2, 0, true),
				}
				var err error
				namespacedSrcNS, err = client.NetworkSets().Update(utils.Ctx, namespacedSrcNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				namespacedDestNS.Spec.Nets = []string{
					c.workloadCIDR(2, 0, true),
					c.workloadCIDR(3, 0, true),
				}
				namespacedDestNS, err = client.NetworkSets().Update(utils.Ctx, namespacedDestNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			}

			Describe("after updating some members in the sets", func() {
				BeforeEach(func() {
					namespacedSrcNS.Spec.Nets = []string{
						// c.workloadCIDR(0, 0, true), removed
						c.workloadCIDR(1, 0, true),
						c.workloadCIDR(2, 0, true),
						c.workloadCIDR(3, 0, true), // added
					}
					var err error
					namespacedSrcNS, err = client.NetworkSets().Update(utils.Ctx, namespacedSrcNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					namespacedDestNS.Spec.Nets = []string{
						// c.workloadCIDR(2, 0, true), removed
						c.workloadCIDR(1, 0, true),
						c.workloadCIDR(3, 0, true),
					}
					namespacedDestNS, err = client.NetworkSets().Update(utils.Ctx, namespacedDestNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					// Now nw[0] isn't in the source set so it can't talk to anyone.
					cc.ExpectNone(nw[0], nw[1])
					cc.ExpectNone(nw[0], nw[2])
					cc.ExpectNone(nw[0], nw[3])

					cc.ExpectNone(nw[1], nw[0]) // not in dest net set
					cc.ExpectNone(nw[1], nw[2]) // not in dest net set
					cc.ExpectSome(nw[1], nw[3])

					cc.ExpectNone(nw[2], nw[0]) // not in dest net set
					cc.ExpectSome(nw[2], nw[1])
					cc.ExpectSome(nw[2], nw[3])

					cc.ExpectNone(nw[3], nw[0])
					cc.ExpectSome(nw[3], nw[1])
					cc.ExpectNone(nw[3], nw[2])
					cc.CheckConnectivity()
				})

				Describe("after reverting the change", func() {
					BeforeEach(resetNetsetsMembers)
					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after switching to zero-CIDR", func() {
				BeforeEach(func() {
					namespacedSrcNS.Spec.Nets = []string{
						c.zeroCIDR,
					}
					var err error
					namespacedSrcNS, err = client.NetworkSets().Update(utils.Ctx, namespacedSrcNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					cc.ExpectNone(nw[0], nw[1]) // not in dest net set
					cc.ExpectSome(nw[0], nw[2])
					cc.ExpectSome(nw[0], nw[3])
					cc.ExpectNone(nw[1], nw[0]) // not in dest net set
					cc.ExpectSome(nw[1], nw[2])
					cc.ExpectSome(nw[1], nw[3])
					cc.ExpectNone(nw[2], nw[0]) // not in dest net set
					cc.ExpectNone(nw[2], nw[1]) // not in dest net set
					cc.ExpectSome(nw[2], nw[3])
					cc.ExpectNone(nw[3], nw[0])
					cc.ExpectNone(nw[3], nw[1])
					cc.ExpectSome(nw[3], nw[2]) // now allowed because all sources are white listed
					cc.CheckConnectivity()
				})

				Describe("after reverting the change", func() {
					BeforeEach(resetNetsetsMembers)
					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after adding a new, overlapping source namespaced network set", func() {
				var namespacedSrcNS2 *api.NetworkSet

				BeforeEach(func() {
					namespacedSrcNS2 = api.NewNetworkSet()
					namespacedSrcNS2.Name = "ns-3"
					namespacedSrcNS2.Namespace = "default"
					namespacedSrcNS2.Spec.Nets = []string{
						c.workloadCIDR(1, 0, true),        // exact match
						c.workloadFullLengthCIDR(2, true), // exact match
						c.workloadCIDR(3, 0, true),        // unique to this net set
					}
					namespacedSrcNS2.Labels = map[string]string{
						"allow-as-source": "",
					}
					var err error
					namespacedSrcNS2, err = client.NetworkSets().Create(utils.Ctx, namespacedSrcNS2, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					cc.ExpectNone(nw[0], nw[1]) // not in dest net set
					cc.ExpectSome(nw[0], nw[2])
					cc.ExpectSome(nw[0], nw[3])
					cc.ExpectNone(nw[1], nw[0]) // not in dest net set
					cc.ExpectSome(nw[1], nw[2])
					cc.ExpectSome(nw[1], nw[3])
					cc.ExpectNone(nw[2], nw[0]) // not in dest net set
					cc.ExpectNone(nw[2], nw[1]) // not in dest net set
					cc.ExpectSome(nw[2], nw[3])
					// 3 is now a valid source.
					cc.ExpectNone(nw[3], nw[0])
					cc.ExpectNone(nw[3], nw[1])
					cc.ExpectSome(nw[3], nw[2])
					cc.CheckConnectivity()
				})

				Describe("after removing the original src netset", func() {
					BeforeEach(func() {
						_, err := client.NetworkSets().Delete(utils.Ctx, namespacedSrcNS.Namespace, namespacedSrcNS.Name, options.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())
					})

					It("should have expected connectivity", func() {
						// nw[0] is no longer a valid source.
						cc.ExpectNone(nw[0], nw[1])
						cc.ExpectNone(nw[0], nw[2])
						cc.ExpectNone(nw[0], nw[3])

						cc.ExpectNone(nw[1], nw[0]) // not in dest net set
						cc.ExpectSome(nw[1], nw[2])
						cc.ExpectSome(nw[1], nw[3])

						cc.ExpectNone(nw[2], nw[0]) // not in dest net set
						cc.ExpectNone(nw[2], nw[1]) // not in dest net set
						cc.ExpectSome(nw[2], nw[3])

						// 3 is still a valid source.
						cc.ExpectNone(nw[3], nw[0])
						cc.ExpectNone(nw[3], nw[1])
						cc.ExpectSome(nw[3], nw[2])
						cc.CheckConnectivity()
					})

					Describe("after removing the new src netset", func() {
						BeforeEach(func() {
							_, err := client.NetworkSets().Delete(utils.Ctx, namespacedSrcNS2.Namespace, namespacedSrcNS2.Name, options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
						})
						It("should have no connectivity", assertNoConnectivity)
					})
				})

				Describe("after removing the new src netset", func() {
					BeforeEach(func() {
						// Make sure the new netset becomes active before we remove it...
						cc.ExpectSome(nw[3], nw[2])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						_, err := client.NetworkSets().Delete(utils.Ctx, namespacedSrcNS2.Namespace, namespacedSrcNS2.Name, options.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())
					})
					It("should have baseline connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after adding duplicate and overlapping members", func() {
				BeforeEach(func() {
					namespacedSrcNS.Spec.Nets = []string{
						c.workloadCIDR(1, 0, true),
						c.workloadCIDR(2, 0, true),
						// Lots of dupes...
						c.workloadFullLengthCIDR(3, true),
						c.workloadFullLengthCIDR(3, true),
						c.workloadCIDR(3, 4, true),
						c.workloadCIDR(3, 0, true),
						c.workloadCIDR(3, 0, true),
						c.workloadCIDR(3, 4, true),
						c.workloadCIDR(3, 0, true),
					}
					var err error
					namespacedSrcNS, err = client.NetworkSets().Update(utils.Ctx, namespacedSrcNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					namespacedDestNS.Spec.Nets = []string{
						// c.workloadCIDR(2, 0, true), // removed
						c.workloadCIDR(1, 0, true),        // added
						c.workloadCIDR(1, 1, true),        // added
						c.workloadFullLengthCIDR(1, true), // added
						c.workloadCIDR(3, 0, true),
					}
					namespacedDestNS, err = client.NetworkSets().Update(utils.Ctx, namespacedDestNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					// Now nw[0] isn't in the source set so it can't talk to anyone.
					cc.ExpectNone(nw[0], nw[1])
					cc.ExpectNone(nw[0], nw[2])
					cc.ExpectNone(nw[0], nw[3])

					cc.ExpectNone(nw[1], nw[0]) // not in dest net set
					cc.ExpectNone(nw[1], nw[2]) // not in dest net set
					cc.ExpectSome(nw[1], nw[3])

					cc.ExpectNone(nw[2], nw[0]) // not in dest net set
					cc.ExpectSome(nw[2], nw[1])
					cc.ExpectSome(nw[2], nw[3])

					cc.ExpectNone(nw[3], nw[0])
					cc.ExpectSome(nw[3], nw[1])
					cc.ExpectNone(nw[3], nw[2])
					cc.CheckConnectivity()
				})

				Describe("after removing some duplicates and adding back some members", func() {
					BeforeEach(func() {
						namespacedSrcNS.Spec.Nets = []string{
							c.workloadCIDR(1, 0, true),
							c.workloadCIDR(2, 0, true),
							c.workloadFullLengthCIDR(3, true), // added
							c.workloadIP(3, true),             // added
						}
						var err error
						namespacedSrcNS, err = client.NetworkSets().Update(utils.Ctx, namespacedSrcNS, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())

						namespacedDestNS.Spec.Nets = []string{
							c.workloadCIDR(0, 0, true),
							c.workloadCIDR(2, 0, true),
							c.workloadCIDR(1, 0, true),
							c.workloadCIDR(3, 0, true),
						}
						namespacedDestNS, err = client.NetworkSets().Update(utils.Ctx, namespacedDestNS, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					})

					It("should have expected connectivity", func() {
						// Now nw[0] isn't in the source set so it can't talk to anyone.
						cc.ExpectNone(nw[0], nw[1])
						cc.ExpectNone(nw[0], nw[2])
						cc.ExpectNone(nw[0], nw[3])

						cc.ExpectSome(nw[1], nw[0])
						cc.ExpectSome(nw[1], nw[2])
						cc.ExpectSome(nw[1], nw[3])

						cc.ExpectSome(nw[2], nw[0])
						cc.ExpectSome(nw[2], nw[1])
						cc.ExpectSome(nw[2], nw[3])

						cc.ExpectSome(nw[3], nw[0])
						cc.ExpectSome(nw[3], nw[1])
						cc.ExpectSome(nw[3], nw[2])
						cc.CheckConnectivity()
					})

					Describe("after reverting the netsets", func() {
						BeforeEach(resetNetsetsMembers)
						It("should have expected connectivity", assertBaselineNetsetsConnectivity)
					})

					Describe("after removing the src netset", func() {
						BeforeEach(func() {
							_, err := client.NetworkSets().Delete(utils.Ctx, namespacedSrcNS.Namespace, namespacedSrcNS.Name, options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
						})
						It("should have no connectivity", assertNoConnectivity)
					})

					Describe("after removing the dest netset", func() {
						BeforeEach(func() {
							_, err := client.NetworkSets().Delete(utils.Ctx, namespacedDestNS.Namespace, namespacedDestNS.Name, options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
						})
						It("should have no connectivity", assertNoConnectivity)
					})
				})

				Describe("after reverting the change", func() {
					BeforeEach(resetNetsetsMembers)
					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after updating rules to allow some traffic based on workload labels", func() {
				BeforeEach(func() {
					pol.Spec.Ingress[0].Source.Selector =
						"has(allow-as-source) || name in {'" + nw[3].Name + "', '" + nw[0].Name + "'}"
					pol = updatePolicy(pol)
				})

				It("should have expected connectivity", func() {
					cc.ExpectNone(nw[0], nw[1]) // not in dest net set
					cc.ExpectSome(nw[0], nw[2])
					cc.ExpectSome(nw[0], nw[3])
					cc.ExpectNone(nw[1], nw[0]) // not in dest net set
					cc.ExpectSome(nw[1], nw[2])
					cc.ExpectSome(nw[1], nw[3])
					cc.ExpectNone(nw[2], nw[0]) // not in dest net set
					cc.ExpectNone(nw[2], nw[1]) // not in dest net set
					cc.ExpectSome(nw[2], nw[3])
					cc.ExpectNone(nw[3], nw[0])
					cc.ExpectNone(nw[3], nw[1])
					cc.ExpectSome(nw[3], nw[2]) // Can now reach
					cc.CheckConnectivity()
				})

				Describe("after removing the src netset", func() {
					BeforeEach(func() {
						_, err := client.NetworkSets().Delete(utils.Ctx, namespacedSrcNS.Namespace, namespacedSrcNS.Name, options.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())
					})
					It("should have expected connectivity", func() {
						cc.ExpectNone(nw[0], nw[1]) // not in dest net set
						cc.ExpectSome(nw[0], nw[2])
						cc.ExpectSome(nw[0], nw[3])

						// Doesn't match as a source.
						cc.ExpectNone(nw[1], nw[0])
						cc.ExpectNone(nw[1], nw[2])
						cc.ExpectNone(nw[1], nw[3])

						// Doesn't match as a source any more.
						cc.ExpectNone(nw[2], nw[0])
						cc.ExpectNone(nw[2], nw[1])
						cc.ExpectNone(nw[2], nw[3])

						cc.ExpectNone(nw[3], nw[0])
						cc.ExpectNone(nw[3], nw[1])
						cc.ExpectSome(nw[3], nw[2]) // Can now reach
						cc.CheckConnectivity()
					})
				})

				Describe("after reverting that change", func() {
					BeforeEach(func() {
						pol.Spec.Ingress[0].Source.Selector = "has(allow-as-source)"
						pol = updatePolicy(pol)
					})

					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})
		})

		Describe("with network sets matching some workloads", func() {
			var (
				srcNS  *api.GlobalNetworkSet
				destNS *api.GlobalNetworkSet
			)

			BeforeEach(func() {
				// We put workloads 0, 1 and 2 in a set that's allowed as a source.
				srcNS = api.NewGlobalNetworkSet()
				srcNS.Name = "ns-1"
				srcNS.Spec.Nets = []string{
					c.workloadCIDR(0, 0, false),
					c.workloadCIDR(1, 0, false),
					c.workloadCIDR(2, 0, false),
				}
				srcNS.Labels = map[string]string{
					"allow-as-source": "",
				}
				var err error
				srcNS, err = client.GlobalNetworkSets().Create(utils.Ctx, srcNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				// We put workloads 2 and 3 in a set that's allowed as destination.
				destNS = api.NewGlobalNetworkSet()
				destNS.Name = "ns-2"
				destNS.Spec.Nets = []string{
					c.workloadCIDR(2, 0, false),
					c.workloadCIDR(3, 0, false),
				}
				destNS.Labels = map[string]string{
					"allow-as-dest": "",
				}
				destNS, err = client.GlobalNetworkSets().Create(utils.Ctx, destNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			assertBaselineNetsetsConnectivity := func() {
				cc.ExpectNone(w[0], w[1]) // not in dest net set
				cc.ExpectSome(w[0], w[2])
				cc.ExpectSome(w[0], w[3])
				cc.ExpectNone(w[1], w[0]) // not in dest net set
				cc.ExpectSome(w[1], w[2])
				cc.ExpectSome(w[1], w[3])
				cc.ExpectNone(w[2], w[0]) // not in dest net set
				cc.ExpectNone(w[2], w[1]) // not in dest net set
				cc.ExpectSome(w[2], w[3])
				// 3 isn't in the source net set so it can't talk to anyone.
				cc.ExpectNone(w[3], w[0])
				cc.ExpectNone(w[3], w[1])
				cc.ExpectNone(w[3], w[2])
				cc.CheckConnectivity()
			}

			It("should have expected connectivity", assertBaselineNetsetsConnectivity)

			resetNetsetsMembers := func() {
				srcNS.Spec.Nets = []string{
					c.workloadCIDR(0, 0, false),
					c.workloadCIDR(1, 0, false),
					c.workloadCIDR(2, 0, false),
				}
				var err error
				srcNS, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				destNS.Spec.Nets = []string{
					c.workloadCIDR(2, 0, false),
					c.workloadCIDR(3, 0, false),
				}
				destNS, err = client.GlobalNetworkSets().Update(utils.Ctx, destNS, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			}

			Describe("after updating some members in the sets", func() {
				BeforeEach(func() {
					srcNS.Spec.Nets = []string{
						// c.workloadCIDR(0, 0, false), removed
						c.workloadCIDR(1, 0, false),
						c.workloadCIDR(2, 0, false),
						c.workloadCIDR(3, 0, false), // added
					}
					var err error
					srcNS, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					destNS.Spec.Nets = []string{
						// c.workloadCIDR(2, 0, false), removed
						c.workloadCIDR(1, 0, false),
						c.workloadCIDR(3, 0, false),
					}
					destNS, err = client.GlobalNetworkSets().Update(utils.Ctx, destNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					// Now w[0] isn't in the source set so it can't talk to anyone.
					cc.ExpectNone(w[0], w[1])
					cc.ExpectNone(w[0], w[2])
					cc.ExpectNone(w[0], w[3])

					cc.ExpectNone(w[1], w[0]) // not in dest net set
					cc.ExpectNone(w[1], w[2]) // not in dest net set
					cc.ExpectSome(w[1], w[3])

					cc.ExpectNone(w[2], w[0]) // not in dest net set
					cc.ExpectSome(w[2], w[1])
					cc.ExpectSome(w[2], w[3])

					cc.ExpectNone(w[3], w[0])
					cc.ExpectSome(w[3], w[1])
					cc.ExpectNone(w[3], w[2])
					cc.CheckConnectivity()
				})

				Describe("after reverting the change", func() {
					BeforeEach(resetNetsetsMembers)
					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after switching to zero-CIDR", func() {
				BeforeEach(func() {
					srcNS.Spec.Nets = []string{
						c.zeroCIDR,
					}
					var err error
					srcNS, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					cc.ExpectNone(w[0], w[1]) // not in dest net set
					cc.ExpectSome(w[0], w[2])
					cc.ExpectSome(w[0], w[3])
					cc.ExpectNone(w[1], w[0]) // not in dest net set
					cc.ExpectSome(w[1], w[2])
					cc.ExpectSome(w[1], w[3])
					cc.ExpectNone(w[2], w[0]) // not in dest net set
					cc.ExpectNone(w[2], w[1]) // not in dest net set
					cc.ExpectSome(w[2], w[3])
					cc.ExpectNone(w[3], w[0])
					cc.ExpectNone(w[3], w[1])
					cc.ExpectSome(w[3], w[2]) // now allowed because all sources are white listed
					cc.CheckConnectivity()
				})

				Describe("after reverting the change", func() {
					BeforeEach(resetNetsetsMembers)
					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after adding a new, overlapping source network set", func() {
				var srcNS2 *api.GlobalNetworkSet

				BeforeEach(func() {
					srcNS2 = api.NewGlobalNetworkSet()
					srcNS2.Name = "ns-3"
					srcNS2.Spec.Nets = []string{
						c.workloadCIDR(1, 0, false),        // exact match
						c.workloadFullLengthCIDR(2, false), // exact match
						c.workloadCIDR(3, 0, false),        // unique to this net set
					}
					srcNS2.Labels = map[string]string{
						"allow-as-source": "",
					}
					var err error
					srcNS2, err = client.GlobalNetworkSets().Create(utils.Ctx, srcNS2, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					cc.ExpectNone(w[0], w[1]) // not in dest net set
					cc.ExpectSome(w[0], w[2])
					cc.ExpectSome(w[0], w[3])
					cc.ExpectNone(w[1], w[0]) // not in dest net set
					cc.ExpectSome(w[1], w[2])
					cc.ExpectSome(w[1], w[3])
					cc.ExpectNone(w[2], w[0]) // not in dest net set
					cc.ExpectNone(w[2], w[1]) // not in dest net set
					cc.ExpectSome(w[2], w[3])
					// 3 is now a valid source.
					cc.ExpectNone(w[3], w[0])
					cc.ExpectNone(w[3], w[1])
					cc.ExpectSome(w[3], w[2])
					cc.CheckConnectivity()
				})

				Describe("after removing the original src netset", func() {
					BeforeEach(func() {
						_, err := client.GlobalNetworkSets().Delete(utils.Ctx, srcNS.Name, options.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())
					})

					It("should have expected connectivity", func() {
						// w[0] is no longer a valid source.
						cc.ExpectNone(w[0], w[1])
						cc.ExpectNone(w[0], w[2])
						cc.ExpectNone(w[0], w[3])

						cc.ExpectNone(w[1], w[0]) // not in dest net set
						cc.ExpectSome(w[1], w[2])
						cc.ExpectSome(w[1], w[3])

						cc.ExpectNone(w[2], w[0]) // not in dest net set
						cc.ExpectNone(w[2], w[1]) // not in dest net set
						cc.ExpectSome(w[2], w[3])

						// 3 is still a valid source.
						cc.ExpectNone(w[3], w[0])
						cc.ExpectNone(w[3], w[1])
						cc.ExpectSome(w[3], w[2])
						cc.CheckConnectivity()
					})

					Describe("after removing the new src netset", func() {
						BeforeEach(func() {
							_, err := client.GlobalNetworkSets().Delete(utils.Ctx, srcNS2.Name, options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
						})
						It("should have no connectivity", assertNoConnectivity)
					})
				})

				Describe("after removing the new src netset", func() {
					BeforeEach(func() {
						// Make sure the new netset becomes active before we remove it...
						cc.ExpectSome(w[3], w[2])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						_, err := client.GlobalNetworkSets().Delete(utils.Ctx, srcNS2.Name, options.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())
					})
					It("should have baseline connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after adding duplicate and overlapping members", func() {
				BeforeEach(func() {
					srcNS.Spec.Nets = []string{
						c.workloadCIDR(1, 0, false),
						c.workloadCIDR(2, 0, false),
						// Lots of dupes...
						c.workloadFullLengthCIDR(3, false),
						c.workloadFullLengthCIDR(3, false),
						c.workloadCIDR(3, 4, false),
						c.workloadCIDR(3, 0, false),
						c.workloadCIDR(3, 0, false),
						c.workloadCIDR(3, 4, false),
						c.workloadCIDR(3, 0, false),
					}
					var err error
					srcNS, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					destNS.Spec.Nets = []string{
						// c.workloadCIDR(2, 0, false), // removed
						c.workloadCIDR(1, 0, false),        // added
						c.workloadCIDR(1, 1, false),        // added
						c.workloadFullLengthCIDR(1, false), // added
						c.workloadCIDR(3, 0, false),
					}
					destNS, err = client.GlobalNetworkSets().Update(utils.Ctx, destNS, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should have expected connectivity", func() {
					// Now w[0] isn't in the source set so it can't talk to anyone.
					cc.ExpectNone(w[0], w[1])
					cc.ExpectNone(w[0], w[2])
					cc.ExpectNone(w[0], w[3])

					cc.ExpectNone(w[1], w[0]) // not in dest net set
					cc.ExpectNone(w[1], w[2]) // not in dest net set
					cc.ExpectSome(w[1], w[3])

					cc.ExpectNone(w[2], w[0]) // not in dest net set
					cc.ExpectSome(w[2], w[1])
					cc.ExpectSome(w[2], w[3])

					cc.ExpectNone(w[3], w[0])
					cc.ExpectSome(w[3], w[1])
					cc.ExpectNone(w[3], w[2])
					cc.CheckConnectivity()
				})

				Describe("after removing some duplicates and adding back some members", func() {
					BeforeEach(func() {
						srcNS.Spec.Nets = []string{
							c.workloadCIDR(1, 0, false),
							c.workloadCIDR(2, 0, false),
							c.workloadFullLengthCIDR(3, false), // added
							c.workloadIP(3, false),             // added
						}
						var err error
						srcNS, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())

						destNS.Spec.Nets = []string{
							c.workloadCIDR(0, 0, false),
							c.workloadCIDR(2, 0, false),
							c.workloadCIDR(1, 0, false),
							c.workloadCIDR(3, 0, false),
						}
						destNS, err = client.GlobalNetworkSets().Update(utils.Ctx, destNS, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					})

					It("should have expected connectivity", func() {
						// Now w[0] isn't in the source set so it can't talk to anyone.
						cc.ExpectNone(w[0], w[1])
						cc.ExpectNone(w[0], w[2])
						cc.ExpectNone(w[0], w[3])

						cc.ExpectSome(w[1], w[0])
						cc.ExpectSome(w[1], w[2])
						cc.ExpectSome(w[1], w[3])

						cc.ExpectSome(w[2], w[0])
						cc.ExpectSome(w[2], w[1])
						cc.ExpectSome(w[2], w[3])

						cc.ExpectSome(w[3], w[0])
						cc.ExpectSome(w[3], w[1])
						cc.ExpectSome(w[3], w[2])
						cc.CheckConnectivity()
					})

					Describe("after reverting the netsets", func() {
						BeforeEach(resetNetsetsMembers)
						It("should have expected connectivity", assertBaselineNetsetsConnectivity)
					})

					Describe("after removing the src netset", func() {
						BeforeEach(func() {
							_, err := client.GlobalNetworkSets().Delete(utils.Ctx, srcNS.Name, options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
						})
						It("should have no connectivity", assertNoConnectivity)
					})

					Describe("after removing the dest netset", func() {
						BeforeEach(func() {
							_, err := client.GlobalNetworkSets().Delete(utils.Ctx, destNS.Name, options.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
						})
						It("should have no connectivity", assertNoConnectivity)
					})
				})

				Describe("after reverting the change", func() {
					BeforeEach(resetNetsetsMembers)
					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})

			Describe("after updating rules to allow some traffic based on workload labels", func() {
				BeforeEach(func() {
					pol.Spec.Ingress[0].Source.Selector =
						"has(allow-as-source) || name in {'" + w[3].Name + "', '" + w[0].Name + "'}"
					pol = updatePolicy(pol)
				})

				It("should have expected connectivity", func() {
					cc.ExpectNone(w[0], w[1]) // not in dest net set
					cc.ExpectSome(w[0], w[2])
					cc.ExpectSome(w[0], w[3])
					cc.ExpectNone(w[1], w[0]) // not in dest net set
					cc.ExpectSome(w[1], w[2])
					cc.ExpectSome(w[1], w[3])
					cc.ExpectNone(w[2], w[0]) // not in dest net set
					cc.ExpectNone(w[2], w[1]) // not in dest net set
					cc.ExpectSome(w[2], w[3])
					cc.ExpectNone(w[3], w[0])
					cc.ExpectNone(w[3], w[1])
					cc.ExpectSome(w[3], w[2]) // Can now reach
					cc.CheckConnectivity()
				})

				Describe("after removing the src netset", func() {
					BeforeEach(func() {
						_, err := client.GlobalNetworkSets().Delete(utils.Ctx, srcNS.Name, options.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())
					})
					It("should have expected connectivity", func() {
						cc.ExpectNone(w[0], w[1]) // not in dest net set
						cc.ExpectSome(w[0], w[2])
						cc.ExpectSome(w[0], w[3])

						// Doesn't match as a source.
						cc.ExpectNone(w[1], w[0])
						cc.ExpectNone(w[1], w[2])
						cc.ExpectNone(w[1], w[3])

						// Doesn't match as a source any more.
						cc.ExpectNone(w[2], w[0])
						cc.ExpectNone(w[2], w[1])
						cc.ExpectNone(w[2], w[3])

						cc.ExpectNone(w[3], w[0])
						cc.ExpectNone(w[3], w[1])
						cc.ExpectSome(w[3], w[2]) // Can now reach
						cc.CheckConnectivity()
					})
				})

				Describe("after reverting that change", func() {
					BeforeEach(func() {
						pol.Spec.Ingress[0].Source.Selector = "has(allow-as-source)"
						pol = updatePolicy(pol)
					})

					It("should have expected connectivity", assertBaselineNetsetsConnectivity)
				})
			})
		})

		AfterEach(func() {
			for ii := range w {
				w[ii].Stop()
			}
			for ii := range nw {
				nw[ii].Stop()
			}
		})
	}

	Context("_BPF-SAFE_ IPv4: Network sets tests with initialized Felix and etcd datastore", func() {
		netsetsConfigV4 := netsetsConfig{ipVersion: 4, zeroCIDR: "0.0.0.0/0"}
		describeConnTests(netsetsConfigV4)
	})

	Context("IPv6: Network sets tests with initialized Felix and etcd datastore", func() {
		netsetsConfigV6 := netsetsConfig{ipVersion: 6, zeroCIDR: "::/0"}
		describeConnTests(netsetsConfigV6)
	})

	Describe("_BPF-SAFE_ churn tests", func() {
		var (
			policies    []*api.GlobalNetworkPolicy
			networkSets []*api.GlobalNetworkSet
		)

		BeforeEach(func() {
			// Start a workload so we have something to add policy to
			w := workload.Run(
				felix,
				"w",
				"default",
				"10.65.0.2",
				"8055",
				"tcp",
			)
			w.Configure(client)

			nw := workload.Run(
				felix,
				"w",
				"default",
				"10.64.0.2",
				"8055",
				"tcp",
			)
			nw.Configure(client)

			// Generate policies and network sets.
			for i := 0; i < numPolicies; i++ {
				pol := api.NewGlobalNetworkPolicy()
				pol.Name = fmt.Sprintf("policy-%d", i)
				pol.Spec = api.GlobalNetworkPolicySpec{
					Selector: "all()",
					Ingress: []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: fmt.Sprintf("label == '%d'", i),
							}},
					},
				}
				policies = append(policies, pol)
			}
			for i := 0; i < numNetworkSets; i++ {
				ns := api.NewGlobalNetworkSet()
				ns.Name = fmt.Sprintf("netset-%d", i)
				ns.Labels = map[string]string{
					"foo":   "bar",
					"baz":   "biff",
					"label": fmt.Sprintf("%d", i%numPolicies),
				}
				nets := generateNets(i * 100)
				ns.Spec = api.GlobalNetworkSetSpec{
					Nets: nets,
				}
				networkSets = append(networkSets, ns)
			}
			log.SetLevel(log.InfoLevel)
		})

		churnPolicies := func(iterations int) {
			log.Info("Churning policies...")
			created := false
			for i := 0; i < iterations; i++ {
				if created {
					for _, pol := range policies {
						log.WithField("policy", pol.Name).Info("Deleting policy")
						cxt, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						_, err := client.GlobalNetworkPolicies().Delete(cxt, pol.Name, options.DeleteOptions{})
						cancel()
						if err != nil {
							log.WithError(err).Panic("Failed to delete policy")
						}
						time.Sleep(13 * time.Millisecond)
					}
				}
				for _, pol := range policies {
					log.WithField("policy", pol.Name).Info("Creating policy")
					cxt, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_, err := client.GlobalNetworkPolicies().Create(cxt, pol, options.SetOptions{})
					cancel()
					if err != nil {
						log.WithError(err).WithField("name", pol.Name).Panic("Failed to add policy")
					}
					time.Sleep(17 * time.Millisecond)
				}
				created = true
			}
		}

		churnNetworkSets := func(iterations int) {
			log.Info("Churning network sets...")
			created := false
			for i := 0; i < iterations; i++ {
				if created {
					for _, ns := range networkSets {
						log.WithField("name", ns.Name).Info("Deleting network set")
						cxt, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						_, err := client.GlobalNetworkSets().Delete(cxt, ns.Name, options.DeleteOptions{})
						cancel()
						if err != nil {
							log.WithError(err).Panic("Failed to delete network set")
						}
						time.Sleep(19 * time.Millisecond)
					}
				}
				for _, ns := range networkSets {
					log.WithField("name", ns.Name).Info("Creating network set")
					cxt, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_, err := client.GlobalNetworkSets().Create(cxt, ns, options.SetOptions{})
					cancel()
					if err != nil {
						log.WithError(err).Panic("Failed to add network set")
					}
					time.Sleep(29 * time.Millisecond)
				}
				created = true
			}
		}

		It("should withstand churn", func() {
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				defer log.Info("Finished churning policies")
				churnPolicies(6)
			}()
			go func() {
				RegisterFailHandler(Fail)
				defer wg.Done()
				defer log.Info("Finished churning network sets")
				churnNetworkSets(3)
			}()

			wg.Wait()

			// getFelixPIDs may return more than one PID, transiently due to Felix calling fork().
			Expect(felix.GetFelixPID()).To(Equal(felixPID))
		})
	})
})

func generateNets(n int) []string {
	var nets []string
	for i := 0; i < n; i++ {
		a := rand.Intn(255)
		b := rand.Intn(255)
		pr := rand.Intn(16) + 16
		netStr := fmt.Sprintf("%d.%d.0.0/%d", a, b, pr)
		_, cidr, err := net.ParseCIDR(netStr)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to parse %s", netStr))
		nets = append(nets, cidr.String())
	}
	return nets
}
