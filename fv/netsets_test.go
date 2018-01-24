// +build fvtests

// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
	"math/rand"
	"strconv"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/options"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/net"
)

const (
	numPolicies    = 20
	numNetworkSets = 100
)

var _ = Context("Network sets churn test with initialized Felix and etcd datastore", func() {

	var (
		etcd     *containers.Container
		felix    *containers.Felix
		felixPID int
		client   client.Interface
	)

	BeforeEach(func() {
		felix, etcd, client = containers.StartSingleNodeEtcdTopology(containers.DefaultTopologyOptions())
		felixPID = felix.GetFelixPID()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			felix.Exec("iptables-save", "-c")
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	Describe("connectivity tests", func() {
		var (
			w  [4]*workload.Workload
			cc *workload.ConnectivityChecker
		)

		createPolicy := func(policy *api.GlobalNetworkPolicy) {
			log.WithField("policy", dumpResource(policy)).Info("Creating policy")
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		BeforeEach(func() {
			for ii := range w {
				iiStr := strconv.Itoa(ii)
				var ports string

				ports = "3000"
				w[ii] = workload.Run(
					felix,
					"w"+iiStr,
					"cali0"+iiStr,
					"10.65."+iiStr+".1", // IPs each in their own /24
					ports,
					"tcp",
				)

				w[ii].DefaultPort = "3000"
				w[ii].Configure(client)
			}

			cc = &workload.ConnectivityChecker{
				Protocol: "tcp",
			}

			pol := api.NewGlobalNetworkPolicy()
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

			createPolicy(pol)
		})

		It("with no matching network sets, should deny all", func() {
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.ExpectNone(w[0], w[3])
			cc.ExpectNone(w[1], w[0])
			cc.ExpectNone(w[1], w[2])
			cc.ExpectNone(w[1], w[3])
			cc.ExpectNone(w[2], w[0])
			cc.ExpectNone(w[2], w[1])
			cc.ExpectNone(w[2], w[3])
			cc.ExpectNone(w[3], w[0])
			cc.ExpectNone(w[3], w[1])
			cc.ExpectNone(w[3], w[2])
			cc.CheckConnectivity()
		})

		It("with network sets matching some workloads, should have expected connectivity", func() {
			srcNS := api.NewGlobalNetworkSet()
			srcNS.Name = "ns-1"
			srcNS.Spec.Nets = []string{
				"10.65.0.0/24",
				"10.65.1.0/24",
				"10.65.2.0/24",
			}
			srcNS.Labels = map[string]string{
				"allow-as-source": "",
			}
			_, err := client.GlobalNetworkSets().Create(utils.Ctx, srcNS, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			destNS := api.NewGlobalNetworkSet()
			destNS.Name = "ns-2"
			destNS.Spec.Nets = []string{
				"10.65.2.0/24",
				"10.65.3.0/24",
			}
			destNS.Labels = map[string]string{
				"allow-as-dest": "",
			}
			_, err = client.GlobalNetworkSets().Create(utils.Ctx, destNS, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

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
		})

		AfterEach(func() {
			for ii := range w {
				w[ii].Stop()
			}
		})
	})

	Describe("churn tests", func() {
		var (
			policies    []*api.GlobalNetworkPolicy
			networkSets []*api.GlobalNetworkSet
		)

		BeforeEach(func() {
			// Start a workload so we have something to add policy to
			w := workload.Run(
				felix,
				"w",
				"cali12345",
				"10.65.0.2",
				"8055",
				"tcp",
			)
			w.Configure(client)

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
				churnPolicies(3)
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
