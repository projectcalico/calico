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
	"io"
	"net/http"
	"regexp"

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

// Repro for https://github.com/projectcalico/calico/issues/12642 — in BPF
// mode, after `kubectl delete node <self>` followed by a Felix restart, the
// host loses all network connectivity (no SSH, no etcd/apiserver) and cannot
// recover on its own. The user-visible expectation is that the *node* stays
// reachable on the network even when Felix is degraded by a missing Node
// resource.
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

		AfterEach(func() {
			// infra.Stop() (with DumpErrorData on failure) is handled by
			// DatastoreDescribe; only the topology-local resources need
			// explicit teardown here.
			if hostW != nil {
				hostW.Stop()
			}
			if externalClient != nil {
				externalClient.Stop()
			}
			tc.Stop()
		})

		// Fast TCP probe — completes in <100ms when the port is reachable,
		// or after the outer `timeout 1` when the BPF dataplane silently
		// drops the SYN (which is how the bug presents). Used by the
		// Consistently polling loops below.
		probeHostSSH := func() error {
			return externalClient.ExecMayFail(
				"timeout", "1", "nc", "-z", tc.Felixes[0].IP, "22",
			)
		}

		// Returns the full /readiness response (status + body table) so
		// gomega matchers can substring-match against the BPFHostIP
		// reporter row.
		readinessReport := func() string {
			resp, err := http.Get(
				fmt.Sprintf("http://%s:9099/readiness", tc.Felixes[0].IP),
			)
			if err != nil {
				return fmt.Sprintf("ERROR: %s", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return fmt.Sprintf("status=%d\n%s", resp.StatusCode, string(body))
		}

		It("should keep host SSH reachable after the Node is deleted", func() {
			By("Verifying host SSH (failsafe port) is reachable before deleting the Node")
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()

			By("Confirming BPFHostIP readiness is ready before the delete")
			Eventually(readinessReport, "10s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=200"),
			))

			By("Deleting the Calico Node object and verifying SSH stays reachable")
			// The BPF endpoint manager deliberately ignores
			// HostMetadataRemove for the local node — tearing through a
			// rebuild while the calico-node pod may be about to be
			// terminated risks leaving the BPF dataplane in an
			// inconsistent state mid-apply. The pinned BPF programs keep
			// running with their last-known HOST_IP cached in their
			// globals. Consistently probes connectivity over a 10s window
			// to verify the dataplane stays healthy through whatever
			// reaction (or lack thereof) Felix has to the delete event.
			_, err := calicoClient.Nodes().Delete(
				context.Background(),
				tc.Felixes[0].Hostname,
				options.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			Consistently(probeHostSSH, "10s", "500ms").Should(Succeed())

			By("Confirming BPFHostIP readiness reports degraded with an absence timestamp")
			Eventually(readinessReport, "10s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=503"),
				ContainSubstring("Host IP unknown"),
				ContainSubstring("IPv4 unknown since"),
			))
		})

		It("should keep host SSH reachable through Node delete, Felix restart, and recovery", func() {
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

			By("Deleting the Calico Node object (simulating `kubectl delete node`)")
			_, err = calicoClient.Nodes().Delete(
				context.Background(),
				felix.Hostname,
				options.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Restarting Felix and verifying SSH stays reachable throughout")
			// This is the core bug repro. Under the bug, the new Felix
			// would: (1) repin the previous Felix's jump maps under
			// old_jumps/<tmp>/, (2) fail to attach new preambles because
			// host IP is nil, (3) clear the err4/err6 anyway so
			// dirtyIfaceNames goes empty, (4) fire the old_jumps cleanup
			// inside the first apply pass, (5) traffic into the still-
			// attached old preambles fails because their tail-call targets
			// are gone. Connectivity drops in steps 4-5 — observed at
			// ~3-5s after the kill in our runs.
			//
			// Under #12688's fix, step (2) succeeds (programs attach with
			// HOST_IP=0), the cleanup is safe, and connectivity holds
			// throughout. We deliberately don't wait for the new PID
			// before starting Consistently — the probe loop naturally
			// covers the kill→exit→restart→first-apply sequence (old
			// programs stay attached across Felix's exit, so connectivity
			// continues while the new Felix comes up). A 15s window at
			// 500ms polling spans the buggy timeline with margin.
			//
			// We deliberately do NOT call Felix.Restart() here, which
			// waits for /readiness=200 — Felix may not reach that state
			// without a Node and that's a separate symptom.
			oldPID := felix.GetFelixPID()
			felix.Exec("kill", "-HUP", fmt.Sprint(oldPID))
			Consistently(probeHostSSH, "15s", "500ms").Should(Succeed())

			By("Confirming Felix actually restarted during the probe window")
			Expect(felix.GetFelixPID()).NotTo(Equal(oldPID))

			By("Confirming readiness reflects the missing Node after restart")
			// Detail is generic ("Host IP not yet known.") rather than
			// "IPv4 unknown since T" — the new Felix has no memory of
			// the previous host IP. The pre-restart "IPv4 unknown
			// since" state from the HostMetadataRemove handler is
			// covered by the Node-delete-only test above.
			Eventually(readinessReport, "30s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=503"),
				ContainSubstring("reporting non-ready"),
			))

			By("Arming a log watcher for the BPF manager picking up the Node's IP")
			hostIPChangedC := felix.WatchStdoutFor(
				regexp.MustCompile(`Host IP changed`),
			)

			By("Re-adding the Calico Node object (simulating recovery)")
			savedNode.ResourceVersion = ""
			savedNode.UID = ""
			_, err = calicoClient.Nodes().Create(
				context.Background(),
				savedNode,
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Felix to pick up the restored host IP")
			// updateHostIP fires, marks every interface dirty, and the next
			// apply pass re-attaches programs with the real HOST_IP. VXLAN
			// return-path encap is also restored at this point. The log
			// fires at the start of that sequence; Consistently below
			// covers the re-attach window.
			Eventually(hostIPChangedC, "30s").Should(BeClosed())

			By("Verifying host SSH stays reachable through the Node-returns re-attach")
			Consistently(probeHostSSH, "10s", "500ms").Should(Succeed())

			By("Confirming readiness returns to ready once the Node is back")
			Eventually(readinessReport, "30s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=200"),
			))
		})

		It("should report readiness degraded when the IP is removed from the Node while the Node remains", func() {
			felix := tc.Felixes[0]

			By("Verifying host SSH is reachable before any change")
			cc.Expect(Some, externalClient, hostW.Port(22))
			cc.CheckConnectivity()

			By("Confirming BPFHostIP readiness is ready before the change")
			Eventually(readinessReport, "10s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=200"),
			))

			By("Capturing the Node spec so we can restore it later")
			savedNode, err := calicoClient.Nodes().Get(
				context.Background(),
				felix.Hostname,
				options.GetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Removing all addresses from the Node (Node still exists, IPs gone)")
			// We must clear BOTH Spec.BGP and Spec.Addresses to drop the
			// IP: extractNodeAddress in the calc graph falls back from
			// the (now-missing) BGP address to Spec.Addresses, so
			// clearing only BGP keeps the IP unchanged. Setting BGP=nil
			// (rather than &NodeBGPSpec{}) is also important — the calc
			// graph treats an explicitly empty BGP spec as Node-deleted
			// and emits HostMetadataRemove instead of HostMetadataUpdate.
			// With both cleared, the calc graph emits HostMetadataUpdate
			// with empty addresses, exercising the "IP removed while
			// Node still exists" path.
			//
			// updateOurHostIP treats this case identically to
			// HostMetadataRemove: the cached lastSeenHostIP is kept so
			// pinned BPF programs continue functioning, and only the
			// BPFHostIP readiness reporter goes degraded.
			modified := savedNode.DeepCopy()
			modified.Spec.BGP = nil
			modified.Spec.Addresses = nil
			_, err = calicoClient.Nodes().Update(
				context.Background(),
				modified,
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			By("Failsafe SSH should still succeed (cached HOST_IP preserved)")
			Consistently(probeHostSSH, "10s", "500ms").Should(Succeed())

			By("Readiness should report degraded with an IPv4-unknown timestamp")
			Eventually(readinessReport, "10s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=503"),
				ContainSubstring("IPv4 unknown since"),
			))

			By("Restoring the Node IP and confirming readiness recovers")
			restored, err := calicoClient.Nodes().Get(
				context.Background(),
				felix.Hostname,
				options.GetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			restored.Spec.BGP = savedNode.Spec.BGP
			restored.Spec.Addresses = savedNode.Spec.Addresses
			_, err = calicoClient.Nodes().Update(
				context.Background(),
				restored,
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			Eventually(readinessReport, "30s", "500ms").Should(SatisfyAll(
				ContainSubstring("BPFHostIP"),
				ContainSubstring("status=200"),
			))
		})
	},
)
