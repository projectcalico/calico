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
	"fmt"
	"math/rand"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
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
		client      *client.Client
		policies    []*api.Policy
		networkSets []*api.NetworkSet
	)

	BeforeEach(func() {
		etcd = containers.RunEtcd()

		client = utils.GetEtcdClient(etcd.IP)
		Eventually(client.EnsureInitialized, "10s", "1s").ShouldNot(HaveOccurred())

		felix = containers.RunFelix(etcd.IP)

		felixNode := api.NewNode()
		felixNode.Metadata.Name = felix.Hostname
		_, err := client.Nodes().Create(felixNode)
		Expect(err).NotTo(HaveOccurred())

		// Start a workload so we have something to add policy to
		w := workload.Run(felix, "w", "cali12345", "10.65.0.2", "8055", "tcp")
		w.Configure(client)

		// Generate policies and network sets.
		for i := 0; i < numPolicies; i++ {
			pol := api.NewPolicy()
			pol.Metadata.Name = fmt.Sprintf("policy-%d", i)
			pol.Spec = api.PolicySpec{
				Selector: "all()",
				IngressRules: []api.Rule{
					{
						Action: "allow",
						Source: api.EntityRule{
							Selector: fmt.Sprintf("label == '%d'", i),
						}},
				},
			}
			policies = append(policies, pol)
		}
		for i := 0; i < numNetworkSets; i++ {
			ns := api.NewNetworkSet()
			ns.Metadata.Name = fmt.Sprintf("netset-%d", i)
			ns.Metadata.Labels = map[string]string{
				"foo":   "bar",
				"baz":   "biff",
				"label": fmt.Sprintf("%d", i%numPolicies),
			}
			nets := generateNets(i * 100)
			ns.Spec = api.NetworkSetSpec{
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

	PIt("should withstand churn", func() {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			defer log.Info("XXXFinished churning policies")
			log.Info("XXXChurning policies...")
			created := false
			for {
				if created {
					for _, pol := range policies {
						log.WithField("policy", pol.Metadata.Name).Info("XXXDeleting policy")
						err := client.Policies().Delete(pol.Metadata)
						if err != nil {
							log.WithError(err).Error("XXXFailed to delete policy")
						}
						time.Sleep(100 * time.Millisecond)
					}
				}
				for _, pol := range policies {
					log.WithField("policy", pol.Metadata.Name).Info("XXXCreating policy")
					_, err := client.Policies().Apply(pol)
					if err != nil {
						log.WithError(err).Error("XXXFailed to add policy")
					}
					time.Sleep(101 * time.Millisecond)
				}
				created = true
			}
		}()
		go func() {
			defer wg.Done()
			defer log.Info("XXXFinished churning network sets")
			log.Info("XXXChurning network sets...")
			created := false
			for {
				if created {
					for _, ns := range networkSets {
						log.WithField("name", ns.Metadata.Name).Info("XXXDeleting network set")
						err := client.NetworkSets().Delete(ns.Metadata)
						if err != nil {
							log.WithError(err).Error("XXXFailed to delete network set")
						}
						time.Sleep(73 * time.Millisecond)
					}
				}
				for _, ns := range networkSets {
					log.WithField("name", ns.Metadata.Name).Info("XXXCreating network set")
					_, err := client.NetworkSets().Apply(ns)
					if err != nil {
						log.WithError(err).Error("XXXFailed to add network set")
					}
					time.Sleep(100 * time.Millisecond)
				}
				created = true
			}
		}()

		wg.Wait()
	})
})

func generateNets(n int) []net.IPNet {
	var nets []net.IPNet
	for i := 0; i < n; i++ {
		a := rand.Intn(255)
		b := rand.Intn(255)
		pr := rand.Intn(16) + 16
		netStr := fmt.Sprintf("%d.%d.0.0/%d", a, b, pr)
		_, cidr, err := net.ParseCIDR(netStr)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to parse %s", netStr))
		nets = append(nets, *cidr)
	}
	return nets
}
