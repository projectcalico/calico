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
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Repro for https://github.com/projectcalico/calico/issues/12642 — when the
// Calico Node object is deleted while Felix is running in BPF mode, the host
// must remain reachable on its failsafe ports.  In the broken state, Felix
// reacts to the loss of host metadata by reprogramming the BPF dataplane in a
// way that drops host management traffic, and the node becomes unreachable.
var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ Felix node delete should preserve host connectivity",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		if !infrastructure.BPFMode() {
			// The bug is BPF-specific.
			return
		}

		var (
			infra          infrastructure.DatastoreInfra
			tc             infrastructure.TopologyContainers
			calicoClient   client.Interface
			hostW          *workload.Workload
			externalClient *containers.Container
			cc             *Checker
		)

		BeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.ExtraEnvVars["FELIX_BPFLogLevel"] = "debug"

			tc, calicoClient = infrastructure.StartNNodeTopology(1, opts, infra)

			// Run a host-networked listener on the failsafe SSH port (22) and a
			// non-failsafe port (8055) so we can distinguish the failsafe path
			// from the policy path.
			hostW = workload.Run(
				tc.Felixes[0],
				"host",
				"default",
				tc.Felixes[0].IP, // host netns
				"8055,22",
				"tcp",
			)

			// External container outside the "cluster" — models traffic from
			// the LAN, e.g. an SSH session into the node.
			externalClient = infrastructure.RunExtClient(infra, "ext-client")

			cc = &Checker{}

			// Wait for BPF programs to come up before doing the connectivity
			// check, otherwise the first probe races the dataplane.
			ensureBPFProgramsAttached(tc.Felixes[0])
		})

		JustAfterEach(func() {
			if !CurrentSpecReport().Failed() {
				return
			}
			// Dump BPF state on the failing felix so we can see why
			// connectivity is broken.
			felix := tc.Felixes[0]
			felix.Exec("calico-bpf", "routes", "dump")
			felix.Exec("calico-bpf", "ifstate", "dump")
			felix.Exec("calico-bpf", "ipsets", "dump")
			felix.Exec("calico-bpf", "conntrack", "dump", "--raw")
			felix.Exec("ip", "addr")
			felix.Exec("ip", "route")
			felix.Exec("bpftool", "-jp", "net")
			// Compare jump-map contents and live prog IDs to the pre-restart
			// snapshot to see whether old prog references were reclaimed.
			felix.Exec("bpftool", "map", "dump", "pinned",
				"/sys/fs/bpf/tc/globals/cali_jump_ing2")
			felix.Exec("bpftool", "map", "dump", "pinned",
				"/sys/fs/bpf/tc/globals/cali_jump_egr2")
			felix.Exec("bpftool", "prog", "show")
			// repinJumpMaps() should preserve the old jump maps under
			// old_jumps/<tmp>/ — dump those too so we can see whether the old
			// preamble's referenced map still has its entries.
			felix.Exec("sh", "-c",
				"ls -laR /sys/fs/bpf/tc/globals/old_jumps/ 2>&1 || true")
			felix.Exec("sh", "-c",
				`for f in /sys/fs/bpf/tc/globals/old_jumps/*/cali_jump_*; do `+
					`echo "=== $f ==="; bpftool map dump pinned "$f"; done 2>&1 || true`)
		})

		AfterEach(func() {
			if hostW != nil {
				hostW.Stop()
			}
			if externalClient != nil {
				externalClient.Stop()
			}
			tc.Stop()
			if CurrentSpecReport().Failed() {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		It("should keep host SSH reachable from outside after the Node is deleted", func() {
			By("Verifying host SSH (failsafe port) is reachable before deleting the Node")
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()

			By("Deleting the Calico Node object (simulating `kubectl delete node`)")
			_, err := calicoClient.Nodes().Delete(
				context.Background(),
				tc.Felixes[0].Hostname,
				options.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// Give Felix a moment to react to the deletion event.  We're
			// looking for a behavioural change, not a transient flap, so a
			// short fixed wait keeps the test deterministic.
			time.Sleep(5 * time.Second)

			By("Verifying host SSH is still reachable after the Node is deleted")
			cc.ResetExpectations()
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()
		})

		It("should keep host SSH reachable after the Node is deleted and Felix restarts", func() {
			felix := tc.Felixes[0]

			By("Verifying host SSH (failsafe port) is reachable before deleting the Node")
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()

			By("Capturing the Node spec so we can restore it later")
			savedNode, err := calicoClient.Nodes().Get(
				context.Background(),
				felix.Hostname,
				options.GetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Snapshotting BPF state BEFORE the Node is deleted (baseline)")
			felix.Exec("calico-bpf", "routes", "dump")
			felix.Exec("bpftool", "map", "dump", "pinned",
				"/sys/fs/bpf/tc/globals/cali_jump_ing2")
			felix.Exec("bpftool", "map", "dump", "pinned",
				"/sys/fs/bpf/tc/globals/cali_jump_egr2")
			felix.Exec("bpftool", "prog", "show")

			By("Deleting the Calico Node object (simulating `kubectl delete node`)")
			_, err = calicoClient.Nodes().Delete(
				context.Background(),
				felix.Hostname,
				options.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Restarting Felix without waiting for /readiness")
			// We deliberately do NOT call Felix.Restart(), which waits for
			// /readiness=200 — Felix can't reach that state without a Node
			// and that's a separate symptom. The user-visible expectation
			// from issue #12642 is that the *node* stays reachable on the
			// network even when Felix is degraded; that's what this test
			// asserts.
			oldPID := felix.GetFelixPID()
			felix.Exec("kill", "-HUP", fmt.Sprint(oldPID))
			Eventually(felix.GetFelixPID, "10s", "100ms").ShouldNot(Equal(oldPID))

			By("Giving the new Felix time to do its first apply pass")
			time.Sleep(10 * time.Second)
			felix.Exec("calico-bpf", "routes", "dump")
			felix.Exec("bpftool", "map", "dump", "pinned",
				"/sys/fs/bpf/tc/globals/cali_jump_ing2")
			felix.Exec("bpftool", "map", "dump", "pinned",
				"/sys/fs/bpf/tc/globals/cali_jump_egr2")
			felix.Exec("bpftool", "prog", "show")

			By("Verifying host SSH is still reachable after Felix restart")
			cc.ResetExpectations()
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()

			By("Verifying the OLD jump maps are still pinned under old_jumps/")
			// repinJumpMaps() moved the previous Felix's maps here; the
			// cleanup gate must NOT have fired (host IP is still unknown),
			// otherwise the old preambles' tail-call targets would be gone.
			out, _ := felix.ExecOutput("sh", "-c",
				"ls /sys/fs/bpf/tc/globals/old_jumps/*/cali_progs_ing2 2>&1 | head -1")
			Expect(out).To(ContainSubstring("/sys/fs/bpf/tc/globals/old_jumps/"),
				"expected at least one old jump map pin under old_jumps/, got: %q", out)

			By("Re-adding the Calico Node object (simulating recovery)")
			savedNode.ResourceVersion = ""
			savedNode.UID = ""
			_, err = calicoClient.Nodes().Create(
				context.Background(),
				savedNode,
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Felix to converge after Node returns")
			// New host metadata triggers updateHostIP which marks all ifaces
			// dirty; the next apply pass attaches new preambles atomically
			// via link.Update and then runs the cleanup that removes
			// old_jumps/. Wait for that cleanup as the convergence signal.
			Eventually(func() string {
				out, _ := felix.ExecOutput("sh", "-c",
					"ls -d /sys/fs/bpf/tc/globals/old_jumps 2>/dev/null || echo absent")
				return out
			}, "60s", "1s").Should(ContainSubstring("absent"),
				"expected old_jumps/ to be cleaned up after Node returns")

			By("Verifying host SSH is still reachable after recovery")
			cc.ResetExpectations()
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()
		})
	},
)
