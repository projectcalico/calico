// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
)

var _ = Context("_IPSets_ Tests for IPset rendering", func() {

	var (
		etcd     *containers.Container
		felix    *infrastructure.Felix
		felixPID int
		client   client.Interface
		infra    infrastructure.DatastoreInfra
		w        *workload.Workload
	)

	BeforeEach(func() {
		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.FelixLogSeverity = "Info"
		topologyOptions.EnableIPv6 = false
		logrus.SetLevel(logrus.InfoLevel)
		felix, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(topologyOptions)
		felixPID = felix.GetFelixPID()
		_ = felixPID
		w = workload.Run(felix, "w", "default", "10.65.0.2", "8085", "tcp")
	})

	AfterEach(func() {
		w.Stop()
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

	It("should render 10000 IP sets quickly", func() {
		// Make 1000 network sets
		sizes := []int{100, 1, 1, 1, 2, 3, 4, 5, 10, 10, 100, 200, 1000}
		const numSets = 1000
		for i := 0; i < 1; i++ {
			ns := api.NewGlobalNetworkSet()
			ns.Name = fmt.Sprintf("netset-%d", i)
			ns.Labels = map[string]string{
				"netset": fmt.Sprintf("netset-%d", i),
			}
			ns.Spec.Nets = generateIPv4s(sizes[i%len(sizes)])
			_, err := client.GlobalNetworkSets().Create(context.TODO(), ns, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		logrus.Info(">>> CREATED NetworkSets")
		// Make a policy that activates them
		for i := 0; i < numSets; i++ {
			pol := api.NewGlobalNetworkPolicy()
			pol.Name = fmt.Sprintf("pol-%d", i)
			pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Selector: fmt.Sprintf("netset == 'netset-0' || netset == 'netset-%d'", i),
					},
				},
			}
			pol.Spec.Selector = "all()"
			_, err := client.GlobalNetworkPolicies().Create(context.TODO(), pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		logrus.Info(">>> CREATED NetworkPolicies")
		// Create a workload that uses the policy.
		baseNumSets := getNumIPSets(felix.Container)
		wep := w.WorkloadEndpoint.DeepCopy()
		w.ConfigureInInfra(infra)
		startTime := time.Now()
		logrus.Info(">>> CREATED Workload")
		Eventually(func() int { return getNumIPSets(felix.Container) }, "240s", "1s").Should(BeNumerically(">", baseNumSets))
		logrus.Info(">>> First IP set programmed at ", time.Since(startTime))
		Eventually(func() int { return getNumIPSets(felix.Container) }, "240s", "1s").Should(BeNumerically(">=", numSets+baseNumSets))
		logrus.Info(">>> All IP sets programmed at ", time.Since(startTime))
		w.RemoveFromInfra(infra)
		logrus.Info(">>> DELETED Workload")
		Eventually(func() int { return getNumIPSets(felix.Container) }, "240s", "1s").Should(BeNumerically("<", numSets+baseNumSets))
		logrus.Info(">>> IP sets started being deleted at ", time.Since(startTime))
		w.WorkloadEndpoint = wep
		w.ConfigureInInfra(infra)
		logrus.Info(">>> RECREATED Workload")
		Eventually(func() int { return getNumIPSets(felix.Container) }, "240s", "1s").Should(BeNumerically(">=", numSets+baseNumSets))
		logrus.Info(">>> All IP sets programmed at ", time.Since(startTime))
		time.Sleep(10 * time.Second)
	})
})

func getNumIPSets(c *containers.Container) int {
	ipsetsOutput, err := c.ExecOutput("ipset", "list", "-name")
	Expect(err).NotTo(HaveOccurred())
	return strings.Count(ipsetsOutput, "\n")
}
