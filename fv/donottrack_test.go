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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = Context("do-not-track policy tests; with 2 nodes", func() {

	var (
		etcd    *containers.Container
		felixes []*containers.Felix
		hostW   [2]*workload.Workload
		client  client.Interface
		cc      *workload.ConnectivityChecker
	)

	BeforeEach(func() {
		options := containers.DefaultTopologyOptions()
		felixes, etcd, client = containers.StartNNodeEtcdTopology(2, options)
		cc = &workload.ConnectivityChecker{}

		// Start a host networked workload on each host for connectivity checks.
		for ii := range felixes {
			hostW[ii] = workload.Run(
				felixes[ii],
				fmt.Sprintf("host%d", ii),
				"", // No interface name means "run in the host's namespace"
				felixes[ii].IP,
				"8055",
				"tcp")
		}
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			felixes[0].Exec("iptables-save", "-c")
			felixes[0].Exec("ip", "r")
		}

		for ii := range felixes {
			felixes[ii].Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	It("before adding policy, should have connectivity between hosts", func() {
		cc.ExpectSome(felixes[0], hostW[1])
		cc.ExpectSome(felixes[1], hostW[0])
		cc.CheckConnectivity()
	})

	Context("after adding host endpoints", func() {
		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "eth0-" + f.Name
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("have no connectivity between hosts", func() {
			cc.ExpectNone(felixes[0], hostW[1])
			cc.ExpectNone(felixes[1], hostW[0])
			cc.CheckConnectivity()
		})
	})

	//
	//Context("with pre-DNAT policy to prevent access from outside", func() {
	//	BeforeEach(func() {
	//		policy := api.NewGlobalNetworkPolicy()
	//		policy.Name = "deny-ingress"
	//		order := float64(20)
	//		policy.Spec.Order = &order
	//		policy.Spec.PreDNAT = true
	//		policy.Spec.ApplyOnForward = true
	//		policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
	//		policy.Spec.Selector = "has(host-endpoint)"
	//		_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
	//		Expect(err).NotTo(HaveOccurred())
	//
	//		hostEp := api.NewHostEndpoint()
	//		hostEp.Name = "felix-eth0"
	//		hostEp.Spec.Node = felix.Hostname
	//		hostEp.Labels = map[string]string{"host-endpoint": "true"}
	//		hostEp.Spec.InterfaceName = "eth0"
	//		_, err = client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
	//		Expect(err).NotTo(HaveOccurred())
	//	})
	//
	//	It("etcd cannot connect", func() {
	//		cc := &workload.ConnectivityChecker{}
	//		cc.ExpectSome(w[0], w[1], 32011)
	//		cc.ExpectSome(w[1], w[0], 32010)
	//		cc.ExpectNone(etcd, w[1], 32011)
	//		cc.ExpectNone(etcd, w[0], 32010)
	//		cc.CheckConnectivity()
	//	})
	//})
})
