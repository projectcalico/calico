// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("NATOutgoing rule rendering test", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.EnableIPv6 = true

		if NFTMode() {
			Skip("NFT mode not supported in this test")
		}

		opts.ExtraEnvVars = map[string]string{
			"FELIX_IptablesNATOutgoingInterfaceFilter": "eth+",
			"FELIX_NATOutgoingExclusions":              "IPPoolsAndHostIPs",
		}
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

		ctx := context.Background()
		ippool := api.NewIPPool()
		ippool.Name = "nat-pool"
		ippool.Spec.CIDR = "10.244.255.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err = client.IPPools().Create(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should have expected restriction on the nat outgoing rule", func() {
		if NFTMode() {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "nat-cali-nat-outgoing")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(".* oifname eth\\+"))
		} else {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "nat")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp("-A cali-nat-outgoing .*-o eth\\+ "))
		}
	})
})

var _ = infrastructure.DatastoreDescribe("NATPortRange rendering test", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.EnableIPv6 = true

		opts.ExtraEnvVars = map[string]string{
			"FELIX_NATPortRange": "32768:65535",
		}
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

		ctx := context.Background()
		ippool := api.NewIPPool()
		ippool.Name = "nat-pool"
		ippool.Spec.CIDR = "10.244.255.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err = client.IPPools().Create(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should have expected rendering", func() {
		if NFTMode() {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "nat-cali-nat-outgoing")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("32768-65535"))
		} else {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "nat")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("32768-65535"))
		}
	})
})
