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
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("VXLAN topology before adding host IPs to IP sets", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
	)

	Context("with mismatched MTU interface pattern", func() {
		BeforeEach(func() {
			infra = getInfra()
			topologyOptions := infrastructure.DefaultTopologyOptions()
			topologyOptions.VXLANMode = api.VXLANModeAlways
			topologyOptions.IPIPEnabled = false

			// Configure the interface pattern so that it doesn't match any host interfaces.
			topologyOptions.ExtraEnvVars["FELIX_MTUIFACEPATTERN"] = "foo"

			felixes, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

			// Wait until the vxlan device appears.
			Eventually(func() error {
				for i, f := range felixes {
					out, err := f.ExecOutput("ip", "link")
					if err != nil {
						return err
					}
					if strings.Contains(out, "vxlan.calico") {
						continue
					}
					return fmt.Errorf("felix %d has no vxlan device", i)
				}
				return nil
			}, "30s", "100ms").ShouldNot(HaveOccurred())
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				for _, felix := range felixes {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ipset", "list")
					felix.Exec("ip", "r")
					felix.Exec("ip", "a")
				}
			}

			for _, felix := range felixes {
				felix.Stop()
			}

			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		It("should configure MTU correctly", func() {
			// We should NOT detect the primary interface's MTU of 1500, and instead default
			// to 1460 due to the mismatched regex. Since VXLAN is enabled, we expect 1460 minus
			// the VXLAN overhead of to show up in the MTU file.
			for _, felix := range felixes {
				Eventually(func() string {
					out, _ := felix.ExecOutput("cat", "/var/lib/calico/mtu")
					return out
				}, "30s", "100ms").Should(ContainSubstring("1410"))
			}

			// Disable VXLAN. We should expect the MTU to change, but still based on the default 1460.
			// Create a default FelixConfiguration
			fc := api.NewFelixConfiguration()
			fc.Name = "default"
			f := false
			fc.Spec.VXLANEnabled = &f
			_, err := client.FelixConfigurations().Create(context.Background(), fc, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// It should now have an MTU of 1460 since there is no encap.
			for _, felix := range felixes {
				Eventually(func() string {
					out, _ := felix.ExecOutput("cat", "/var/lib/calico/mtu")
					return out
				}, "30s", "100ms").Should(ContainSubstring("1460"))
			}
		})
	})
})
