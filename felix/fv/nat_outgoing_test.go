//go:build fvtests

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("NAT-outgoing rule rendering test", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra          infrastructure.DatastoreInfra
		felix          *infrastructure.Felix
		client         client.Interface
		dumpedDiags    bool
		externalClient *containers.Container
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		dumpedDiags = false
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars = map[string]string{
			"FELIX_IptablesNATOutgoingInterfaceFilter": "eth+",
		}
		felix, client = infrastructure.StartSingleNodeTopology(opts, infra)

		ctx := context.Background()
		ippool := api.NewIPPool()
		ippool.Name = "nat-pool"
		ippool.Spec.CIDR = "10.244.255.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err = client.IPPools().Create(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	// Utility function to dump diags if the test failed.  Should be called in the inner-most
	// AfterEach() to dump diags before the test is torn down.  Only the first call for a given
	// test has any effect.
	dumpDiags := func() {
		if !CurrentSpecReport().Failed() || dumpedDiags {
			return
		}
		iptSave, err := felix.ExecOutput("iptables-save", "-c")
		if err == nil {
			log.Info("iptables-save:\n" + iptSave)
		}
		dumpedDiags = true
		infra.DumpErrorData()
	}

	AfterEach(func() {
		dumpDiags()
		felix.Stop()
		infra.Stop()
		externalClient.Stop()
	})

	It("should have expected restriction on the nat outgoing rule", func() {
		Eventually(func() string {
			output, _ := felix.ExecOutput("iptables-save", "-t", "nat")
			return output
		}, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp("-A cali-nat-outgoing .*-o eth\\+ "))
	})
})
