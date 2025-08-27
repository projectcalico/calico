// Copyright (c) 2020 Tigera, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networking

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("MTU"),
	describe.WithCategory(describe.Networking),
	"Automatic MTU tests",
	func() {
		// Determine platform and thus expected MTU.
		f := utils.NewDefaultFramework("calico-mtu")

		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var clientPod *conncheck.Client

		BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// Run the test pod as root and with NET_RAW capabiltiies to allow access to network interfaces.
			customizer := func(pod *v1.Pod) {
				pod.Spec.SecurityContext = &v1.PodSecurityContext{RunAsUser: ptr.To[int64](0)}
				pod.Spec.Containers[0].SecurityContext = &v1.SecurityContext{
					RunAsUser:    ptr.To[int64](0),
					Capabilities: &v1.Capabilities{Add: []v1.Capability{v1.Capability("NET_RAW")}},
				}
			}
			checker = conncheck.NewConnectionTester(f)
			clientPod = conncheck.NewClient("mtu", f.Namespace, conncheck.WithClientCustomizer(customizer))
			checker.AddClient(clientPod)
			checker.Deploy()
		})

		It("should select the correct MTU for the platform", func() {
			// Get the MTU within the pod.
			out, err := conncheck.ExecInPod(clientPod.Pod(), "sh", "-c", "ip link show eth0")
			Expect(err).NotTo(HaveOccurred())

			// // Get the MTU of the underlying network.
			// underlayMTU, err := underlayMTU()
			// Expect(err).NotTo(HaveOccurred())
			//
			// // Get expected overhead.
			// overhead, err := encapOverhead(cli)
			// Expect(err).NotTo(HaveOccurred())
			expectedMTU := utils.ExpectedPodMTU(f)
			Expect(expectedMTU).NotTo(BeNil(), "Expected MTU should not be nil")

			// Expect the MTU to match the platform and encap.
			Expect(out).To(ContainSubstring(fmt.Sprintf("mtu %d", *expectedMTU)))
		})
	})

// encapOverhead returns the expected overhead based on enabled encapsulations.
// TODO: This should, strictly speaking, also check daemonset env vars and config files to determine enabled encap.
//
//	However, we don't currently use those methods to enable this in felix in any of our manifests.
func encapOverhead(cli ctrlclient.Client) (int, error) {
	// Get FelixConfig to look at Wireguard config and IPIP/VXLAN override configs
	felixConfig := v3.NewFelixConfiguration()
	err := cli.Get(context.TODO(), ctrlclient.ObjectKey{Name: "default"}, felixConfig)
	if err != nil {
		return 0, err
	}

	// Get IPIP, IPv4 VXLAN and IPv6 VXLAN encapsulation from the existing IP pools
	poolIPIP, poolVXLAN, poolVXLANV6, err := utils.GetEncapsulationFromPools(cli)
	if err != nil {
		return 0, err
	}

	// The pod MTU can only be the same for IPv4 and IPv6, thus it must be the
	// smallest value possible according to the enabled encapsulation. Hence,
	// return the largest overhead.
	vxlanV6 := felixConfig.Spec.VXLANEnabled
	if vxlanV6 == nil {
		vxlanV6 = &poolVXLANV6
	}
	if vxlanV6 != nil && *vxlanV6 {
		// IPv6 VXLAN is enabled, overhead is 70 bytes.
		return 70, nil
	}

	wg := felixConfig.Spec.WireguardEnabled
	if wg != nil && *wg {
		// IPv4 Wireguard is enabled, overhead is 60 bytes.
		return 60, nil
	}

	vxlan := felixConfig.Spec.VXLANEnabled
	if vxlan == nil {
		vxlan = &poolVXLAN
	}
	if vxlan != nil && *vxlan {
		// IPv4 VXLAN is enabled, overhead is 50 bytes.
		return 50, nil
	}

	ipip := felixConfig.Spec.IPIPEnabled
	if ipip == nil {
		ipip = &poolIPIP
	}
	if ipip != nil && *ipip {
		// IPv4 IPIP is enabled, overhead is 20 bytes.
		return 20, nil
	}

	// No encap is enabled, overhead is 0.
	return 0, nil
}
