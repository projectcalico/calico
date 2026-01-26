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
	"fmt"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
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

		ginkgo.BeforeEach(func() {
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

		ginkgo.It("should select the correct MTU for the platform", func() {
			// Get the MTU within the pod.
			out, err := conncheck.ExecInPod(clientPod.Pod(), "sh", "-c", "ip link show eth0")
			Expect(err).NotTo(HaveOccurred())

			expectedMTU := utils.ExpectedPodMTU(f)
			Expect(expectedMTU).NotTo(BeNil(), "Expected MTU should not be nil")

			// Expect the MTU to match the platform and encap.
			Expect(out).To(ContainSubstring(fmt.Sprintf("mtu %d", *expectedMTU)))
		})
	})
