// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"encoding/base64"
	"net"
	"regexp"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/timeshim"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// For same-node workload-to-workload traffic the source's program can hand the
// packet straight to the destination's network namespace with
// bpf_redirect_peer, skipping the destination's own program. It does so on the
// strength of the conntrack verdict alone, so an entry that wrongly reads as
// approved by both endpoints turns the fast path into a policy bypass.
//
// Entries can reach that state: a host-endpoint program approves the leg facing
// away from the host, which is the wrong leg when the destination is a local
// workload whose route has not been programmed yet. Rather than try to hit that
// window, these tests write the resulting entry into the conntrack map directly
// and check that the destination's policy is still enforced.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ BPF peer redirect policy enforcement",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		if !BPFMode() {
			// Peer redirect only exists in the BPF dataplane.
			return
		}

		const (
			clientIP   = "10.65.0.2"
			serverIP   = "10.65.0.3"
			serverPort = 8055
			// Pinned so the forged conntrack entry and the connection attempt
			// agree on the 5-tuple.
			srcPort = 12345
		)

		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			w            [2]*workload.Workload
			cc           *Checker
		)

		BeforeEach(func() {
			infra = getInfra()
			tc, calicoClient = infrastructure.StartSingleNodeTopology(
				infrastructure.DefaultTopologyOptions(), infra)
			infra.AddDefaultAllow()

			for i, ip := range []string{clientIP, serverIP} {
				name := "w" + strconv.Itoa(i)
				w[i] = workload.Run(tc.Felixes[0], name, "default", ip,
					strconv.Itoa(serverPort), "tcp")
				w[i].WorkloadEndpoint.Labels = map[string]string{"name": name}
				w[i].ConfigureInInfra(infra)
			}

			cc = &Checker{Protocol: "tcp"}
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				tc.Felixes[0].Exec("calico-bpf", "conntrack", "dump", "--raw")
				tc.Felixes[0].Exec("calico-bpf", "counters", "dump")
				tc.Felixes[0].Exec("calico-bpf", "policy", "dump", w[1].InterfaceName, "all")
			}

			for i := range w {
				w[i].Stop()
			}
			tc.Stop()
			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		denyClientToServer := func() {
			pol := api.NewGlobalNetworkPolicy()
			pol.Name = "deny-w0-to-w1"
			pol.Spec.Selector = "name == 'w1'"
			pol.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			pol.Spec.Ingress = []api.Rule{{
				Action: api.Deny,
				Source: api.EntityRule{Selector: "name == 'w0'"},
			}}
			_, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		// poisonConntrack writes the entry a host-endpoint program leaves
		// behind: a normal TCP entry for the client-to-server tuple with both
		// legs approved, so the source's program reads the flow as established
		// and fully approved.
		//
		// The key's A and B sides are ordered by (address, port), lowest first.
		// clientIP:srcPort sorts below serverIP:serverPort, so the client is A.
		poisonConntrack := func() {
			leg := conntrack.Leg{Approved: true, SynSeen: true, AckSeen: true}
			val := conntrack.NewValueNormal(
				time.Duration(timeshim.RealTime().KTimeNanos()), 0, leg, leg)
			const protoTCP = 6
			key := conntrack.NewKey(protoTCP,
				net.ParseIP(clientIP), srcPort, net.ParseIP(serverIP), serverPort)

			tc.Felixes[0].Exec("calico-bpf", "conntrack", "write",
				base64.StdEncoding.EncodeToString(key[:]),
				base64.StdEncoding.EncodeToString(val[:]))
		}

		// expectConntrackConsulted fails if the forged entry was never looked
		// up. Without it a mistake in the key would leave the entry inert and
		// the deny would pass for the wrong reason. Every lookup bumps the
		// packet count on the leg the packet travels, which is A2B here.
		expectConntrackConsulted := func() {
			out, err := tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump", "--raw")
			Expect(err).NotTo(HaveOccurred())

			re := regexp.MustCompile(
				`ConntrackKey\{proto=6 ` + regexp.QuoteMeta(clientIP) + `:` + strconv.Itoa(srcPort) +
					` <-> ` + regexp.QuoteMeta(serverIP) + `:` + strconv.Itoa(serverPort) +
					`\}.*A2B:\{Bytes:\d+ Packets:(\d+)`)
			m := re.FindStringSubmatch(out)
			Expect(m).NotTo(BeNil(), "forged conntrack entry not found in:\n%s", out)
			Expect(strconv.Atoi(m[1])).To(BeNumerically(">", 0),
				"forged conntrack entry was never looked up, so the test proves nothing")
		}

		It("should enforce the destination's policy on a new connection that hits an entry approved by both legs", func() {
			By("checking the workloads can talk before any policy is applied")
			cc.ExpectSome(w[0], w[1].Port(serverPort))
			cc.CheckConnectivity()

			By("denying the client on the server's ingress")
			denyClientToServer()
			cc.ResetExpectations()
			cc.ExpectNone(w[0], w[1].Port(serverPort))
			cc.CheckConnectivity()

			By("writing a conntrack entry that reads as approved by both endpoints")
			poisonConntrack()

			By("checking the deny still applies to a connection matching that entry")
			cc.ResetExpectations()
			cc.Expect(None, w[0], w[1].Port(serverPort), ExpectWithSrcPort(srcPort))
			cc.CheckConnectivity()

			expectConntrackConsulted()
		})
	})
