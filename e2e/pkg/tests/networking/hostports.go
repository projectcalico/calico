// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package networking

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

const hostport = 8080

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	describe.WithFeature("HostPorts"),
	describe.WithSerial(),
	"HostPorts tests",
	func() {
		f := utils.NewDefaultFramework("hostports")
		var checker conncheck.ConnectionTester
		var server *conncheck.Server
		var client1 *conncheck.Client

		BeforeEach(func() {
			// Define a function to set the HostPort on the server pod.
			hostPortSetter := func(pod *v1.Pod) {
				pod.Spec.Containers[0].Ports = []v1.ContainerPort{
					{
						ContainerPort: int32(80),
						HostPort:      int32(hostport),
						Protocol:      v1.ProtocolTCP,
					},
				}
			}
			// Create a connection checker with a client and server.
			checker = conncheck.NewConnectionTester(f)
			server = conncheck.NewServer("server", f.Namespace, conncheck.WithPorts(80), conncheck.WithServerPodCustomizer(hostPortSetter))
			client1 = conncheck.NewClient("client", f.Namespace)
			checker.AddServer(server)
			checker.AddClient(client1)
			checker.Deploy()
		})

		AfterEach(func() {
			checker.Stop()
		})

		text := fmt.Sprintf("with host port resources active on :%d", hostport)
		Context(text, func() {
			framework.ConformanceIt("should support Pod HostPorts", func() {
				checker.ExpectSuccess(client1, server.HostPorts(hostport)...)   // Expect success on the correct host port.
				checker.ExpectFailure(client1, server.HostPorts(hostport+1)...) // Expect failure on an incorrect host port.
				checker.Execute()
			})
		})
	})
