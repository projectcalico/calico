// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"

	"context"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"

	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ ethtool tests",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {

		if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
			// Non-BPF run.
			return
		}

		var (
			infra        infrastructure.DatastoreInfra
			felixes      []*infrastructure.Felix
			felix        *infrastructure.Felix
			options      infrastructure.TopologyOptions
			calicoClient client.Interface
		)

		BeforeEach(func() {
			infra = getInfra()
			options = infrastructure.DefaultTopologyOptions()
		})

		JustBeforeEach(func() {
			felixes, calicoClient = infrastructure.StartNNodeTopology(1, options, infra)
			felix = felixes[0]
		})

		AfterEach(func() {
			for _, f := range felixes {
				f.Stop()
			}
			infra.Stop()
		})

		Context("With Felix configuration set GRO disabled on eth0", func() {
			It("should detected by the ethtool in Felix to assert update made successfully ", func() {

				// Ensure Generic Receive Offload [GRO] enabled by default.
				err := felix.ExecMayFail("ethtool", "-K", "eth0", "gro", "on")
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() string {
					out, _ := felix.ExecOutput("ethtool", "-k", "eth0")
					return out
				}, "15s", "1s").Should(ContainSubstring("generic-receive-offload: on"))

				// Create new Felix configuaration and disabled GRO for eth0.
				fc := api.NewFelixConfiguration()
				fc.Name = "default"
				fc.Spec.BPFLogLevel = "Debug"
				fc.Spec.BPFDisableGROForIfaces = "eth0"

				fc, err = calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Restart Felix and assert GRO disabled on eth0 accordingly.
				felix.Restart()
				Eventually(func() string {
					out, _ := felix.ExecOutput("ethtool", "-k", "eth0")
					return out
				}, "15s", "1s").Should(ContainSubstring("generic-receive-offload: off"))
			})
		})
	})
