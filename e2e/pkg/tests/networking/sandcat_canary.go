// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"github.com/onsi/ginkgo/v2"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	"sandcat canary (always fails)",
	func() {
		f := utils.NewDefaultFramework("sandcat-canary")
		var checker conncheck.ConnectionTester
		var server conncheck.Server
		var client conncheck.Client

		ginkgo.BeforeEach(func() {
			checker = conncheck.NewConnectionTester(f)
			server = conncheck.NewServer("server", f.Namespace, conncheck.WithPorts(80))
			client = conncheck.NewClient("client", f.Namespace)
			checker.AddServer(server)
			checker.AddClient(client)
			checker.Deploy()
		})

		ginkgo.AfterEach(func() {
			checker.Stop()
		})

		framework.ConformanceIt("should block a client that no policy blocks", func() {
			checker.ExpectFailure(client, server.ClusterIPs()...)
			checker.Execute()
		})
	})
