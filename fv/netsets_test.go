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
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

var _ = Context("with initialized Felix and etcd datastore", func() {

	var (
		etcd        *containers.Container
		felix       *containers.Container
		felixPID    int
		client      client.Interface
		policies    []*api.GlobalNetworkPolicy
		networkSets []*api.GlobalNetworkSet
	)

	getFelixPIDs := func() []int {
		return felix.GetPIDs("calico-felix")
	}

	updateFelixPID := func() {
		// Get Felix's PID.  This retry loop ensures that we don't get tripped up if we see multiple
		// PIDs, which can happen transiently when Felix restarts/forks off a subprocess.
		start := time.Now()
		for {
			pids := getFelixPIDs()
			if len(pids) == 1 {
				felixPID = pids[0]
				break
			}
			Expect(time.Since(start)).To(BeNumerically("<", time.Second))
			time.Sleep(50 * time.Millisecond)
		}
	}

	BeforeEach(func() {
		felix, etcd, client = containers.StartSingleNodeEtcdTopology(containers.TopologyOptions{
			FelixLogSeverity: "info",
		})
		updateFelixPID()

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
		Eventually(getFelixPIDs).Should(ConsistOf(felixPID))
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
