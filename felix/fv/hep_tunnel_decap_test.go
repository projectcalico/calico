// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// This file tests the enforcement of HostEndpoint policy on traffic that
// arrives on vxlan.calico after VXLAN decapsulation in BPF mode.
//
// Traffic path under test:
//
//	Pod w[0] on Felix[0] (10.65.0.2) sends TCP to pod w[1] on Felix[1] (10.65.1.2).
//	Felix[0] eth0 BPF (FROM_WEP path): looks up the BPF route map, finds a tunneled
//	route for 10.65.1.0/26 via Felix[1]'s underlay IP, VXLAN-encapsulates the packet
//	and redirects it to vxlan.calico.
//	Felix[1] eth0 receives the outer VXLAN frame; the from_hep BPF program auto-allows
//	VXLAN traffic from a known Calico peer.
//	The kernel decapsulates the inner TCP packet; it arrives on Felix[1]'s vxlan.calico.
//	The TC BPF program on vxlan.calico (from_vxlan, EpTypeVXLAN) enforces HEP policy.
//
// Without any HEP, the jump-map entry for EpTypeVXLAN is pre-loaded with DefPolicyAllow
// and all traffic passes.  Once a wildcard HEP is created (with no attached policy or
// an explicit deny policy), Felix compiles and installs the correct program, which
// SHOULD cause traffic to be blocked.
//
// KNOWN BUG (regression test):
//
//	These tests currently FAIL due to a BPF dataplane bug: the conntrack entry created
//	by Felix[1]'s eth0 from_hep program (which auto-allows the outer VXLAN frame from
//	a known Calico peer) carries a "from HEP tun" approval flag.  When the kernel
//	decapsulates the inner TCP packet and it arrives on vxlan.calico, the from_vxlan
//	BPF program performs a conntrack lookup, finds the "from HEP tun" flag, and
//	auto-approves the packet via:
//	  "CT-ALL approved source side - from HEP tun allow_return=0"
//	This happens BEFORE the HEP policy is consulted, so the compiled deny policy
//	on vxlan.calico is never reached.  Felix correctly compiles and loads the policy
//	(verified by the debug JSON file appearing), but the CT bypass prevents enforcement.
//
//	These tests serve as regression tests: they should PASS once the CT bypass logic
//	correctly limits its scope so that packets arriving on vxlan.calico must still be
//	evaluated against the HEP policy compiled for that interface.
//
// Each test includes a baseline connectivity check (no HEP → traffic must flow) to
// confirm the infrastructure is working before the HEP is added.  If the baseline
// fails, the test setup is broken, not the HEP enforcement logic.

var _ = infrastructure.DatastoreDescribe(
	"BPF HEP tunnel decap policy enforcement",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {

		var (
			infra   infrastructure.DatastoreInfra
			tc      infrastructure.TopologyContainers
			cClient client.Interface
			// w[0] lives on Felix[0] (10.65.0.2), w[1] lives on Felix[1] (10.65.1.2).
			// Traffic from w[0] to w[1] is VXLAN-encapsulated by Felix[0]'s eth0 BPF
			// (FROM_WEP path) and decapsulated by the kernel on Felix[1], arriving on
			// Felix[1]'s vxlan.calico where HEP policy is enforced.
			w  [2]*workload.Workload
			cc *connectivity.Checker
		)

		BeforeEach(func() {
			if !BPFMode() {
				Skip("This test targets a BPF-specific product bug; iptables/nftables correctly enforces HEP on all tunnel paths")
			}

			infra = getInfra()

			// Use VXLAN-always so that all cross-node traffic (including pod-to-pod)
			// is encapsulated through the vxlan.calico device.
			topologyOptions := infrastructure.DefaultTopologyOptions()
			topologyOptions.IPIPMode = api.IPIPModeNever
			topologyOptions.VXLANMode = api.VXLANModeAlways
			topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(
				topologyOptions.IPPoolCIDR,
				topologyOptions.IPv6PoolCIDR,
			)
			// Delay Felix start until node resources exist with VXLAN tunnel addresses,
			// matching the pattern used by BPF tunnel tests in bpf_test.go. This avoids
			// a race where Felix starts before the node annotations are written and then
			// needs more than 1 minute to fully converge the vxlan.calico interface.
			topologyOptions.DelayFelixStart = true
			topologyOptions.TriggerDelayedFelixStart = true

			tc, cClient = infrastructure.StartNNodeTopology(2, topologyOptions, infra)

			// AddDefaultAllow installs a profile that allows all workload-to-workload
			// traffic.  This means WEP egress/ingress policy on the pod veth interfaces
			// permits traffic; the only potential block is the HEP policy on vxlan.calico.
			infra.AddDefaultAllow()

			// Create one regular pod workload per node.  These workloads have their own
			// network namespace and a pod-CIDR IP, so outbound traffic from w[0] follows
			// the FROM_WEP BPF code path on Felix[0]'s eth0.  That path performs VXLAN
			// encapsulation when the BPF route map shows a tunneled route for the
			// destination — which is exactly the case for cross-node pod traffic in
			// VXLAN-always mode.
			for ii := range w {
				wName := fmt.Sprintf("w%d", ii)
				wIP := fmt.Sprintf("10.65.%d.2", ii)
				// Register the IP in IPAM so Felix computes block affinities and
				// programs the BPF route map with a tunneled route for the remote
				// workload.  Without this step Felix does not add a route for the
				// remote pod CIDR and cross-node connectivity fails in BPF mode.
				infrastructure.AssignIP(wName, wIP, tc.Felixes[ii].Hostname, cClient)
				w[ii] = workload.Run(
					tc.Felixes[ii],
					wName,
					"default",
					wIP,
					"8055",
					"tcp",
				)
				w[ii].WorkloadEndpoint.Labels = map[string]string{"name": w[ii].Name}
				w[ii].ConfigureInInfra(infra)
			}

			// Wait for Felix to attach BPF programs to all expected interfaces including
			// vxlan.calico AND the workload veth interfaces.  This is done AFTER workload
			// creation so that felix.Workloads is populated and ensureAllNodesBPFProgramsAttached
			// includes the veth interfaces in its wait condition.  Without the veth BPF programs
			// the FROM_WEP code path (which performs VXLAN encapsulation) is not active and
			// cross-node connectivity will fail.
			ensureAllNodesBPFProgramsAttached(tc.Felixes)

			cc = &connectivity.Checker{}
		})

		It("should block pod traffic arriving via VXLAN tunnel when a wildcard HEP with default-deny is active", func() {
			// Baseline: with no HEP configured anywhere, cross-node pod traffic
			// via the VXLAN tunnel should flow freely.  This verifies that the test
			// workloads are correctly listening and that the VXLAN path is functional
			// before we add policy.
			By("baseline: pod-to-pod traffic flows freely when no HEP is configured")
			baselineCC := &connectivity.Checker{}
			baselineCC.ExpectSome(w[0], w[1])
			baselineCC.CheckConnectivity()

			// Create a wildcard all-interfaces HEP only on Felix[1] (the receiver).
			// Felix[0] has no HEP and is therefore unrestricted; the BPF program on
			// Felix[0]'s eth0 (FROM_WEP path) will VXLAN-encapsulate the packet and
			// forward it normally.
			//
			// Felix[1]'s HEP has no attached policy or profile, so the Calico
			// default-deny applies: all traffic arriving on any of Felix[1]'s
			// interfaces — including the decapped inner packet arriving on
			// vxlan.calico — is denied after the HEP is created.
			//
			// Traffic path after adding the HEP:
			//   w[0] → Felix[0] veth (FROM_WEP, WEP egress allow) → Felix[0] eth0
			//   BPF VXLAN encap → Felix[1] eth0 from_hep auto-allows outer VXLAN
			//   → kernel decap → vxlan.calico from_vxlan → HEP default-deny → DROP
			hep := api.NewHostEndpoint()
			hep.Name = "hep-" + tc.Felixes[1].Name
			hep.Labels = map[string]string{
				"host-endpoint": "true",
				"hostname":      tc.Felixes[1].Hostname,
			}
			hep.Spec.Node = tc.Felixes[1].Hostname
			hep.Spec.ExpectedIPs = []string{tc.Felixes[1].IP}
			hep.Spec.InterfaceName = "*" // wildcard: covers all interfaces on Felix[1]
			_, err := cClient.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Wait for Felix to compile and load the HEP default-deny program on vxlan.calico.
			// Felix writes the policy debug JSON file when it compiles a real program for the
			// interface, replacing the DefPolicyAllow placeholder in the jump map.
			// ensureAllNodesBPFProgramsAttached only checks FlgIPv4Ready (set at initial TC
			// attachment) and does not detect subsequent policy recompilations, so we cannot
			// use it here.
			Eventually(func() bool {
				out, err := tc.Felixes[1].ExecOutput(
					"cat", "/var/run/calico/bpf/policy/vxlan.calico_ingress_v4.json")
				return err == nil && strings.Contains(out, "vxlan.calico")
			}, "30s", "1s").Should(BeTrue(),
				"Felix should compile and load HEP default-deny policy for vxlan.calico ingress")

			By("pod-to-pod traffic via VXLAN tunnel should be blocked by HEP default-deny on vxlan.calico")
			cc.ExpectNone(w[0], w[1])
			cc.CheckConnectivity()
		})

		It("should block pod traffic arriving via VXLAN tunnel when an explicit deny policy targets the HEP", func() {
			// Baseline: confirm traffic flows freely in both directions before any HEP.
			By("baseline: pod-to-pod traffic flows freely in both directions when no HEP is configured")
			baselineCC := &connectivity.Checker{}
			baselineCC.ExpectSome(w[0], w[1])
			baselineCC.ExpectSome(w[1], w[0])
			baselineCC.CheckConnectivity()

			// Create wildcard HEPs on BOTH nodes with an explicit GlobalNetworkPolicy
			// that denies all ingress but allows all egress.  The explicit egress Allow
			// rule ensures that the sending node's HEP does not block the outgoing
			// encapsulated packet — isolating the ingress enforcement on the receiving
			// node's vxlan.calico.
			//
			// Expected (correct) behaviour:
			//   The inner TCP packet that arrives on the receiver's vxlan.calico after
			//   VXLAN decapsulation must be matched by the "deny ingress" rule and
			//   dropped in both directions.
			for _, f := range tc.Felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "hep-" + f.Name
				hep.Labels = map[string]string{
					"host-endpoint": "true",
					"hostname":      f.Hostname,
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				hep.Spec.InterfaceName = "*"
				_, err := cClient.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			// Explicit deny ingress, allow egress.  This is intentionally different from
			// the default-deny test above: the deny here is a concrete policy rule, not
			// just the absence of an allow.  If the two mechanisms were ever implemented
			// differently in the BPF dataplane this test catches that gap.
			denyIngress := api.NewGlobalNetworkPolicy()
			denyIngress.Name = "hep-deny-ingress-allow-egress"
			denyIngress.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			denyIngress.Spec.Egress = []api.Rule{{Action: api.Allow}}
			denyIngress.Spec.Selector = `has(host-endpoint)`
			_, err := cClient.GlobalNetworkPolicies().Create(utils.Ctx, denyIngress, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Wait for the explicit deny policy to be compiled and loaded on vxlan.calico
			// ingress on BOTH nodes.  bpfCheckIfGlobalNetworkPolicyProgrammed reads the
			// policy debug JSON that Felix writes when it compiles and installs a new BPF
			// program.  ensureAllNodesBPFProgramsAttached only checks FlgIPv4Ready (set at
			// initial TC attachment) and is not sensitive to subsequent policy updates.
			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(
					tc.Felixes[0], "vxlan.calico", "ingress",
					"hep-deny-ingress-allow-egress", "deny", false) &&
					bpfCheckIfGlobalNetworkPolicyProgrammed(
						tc.Felixes[1], "vxlan.calico", "ingress",
						"hep-deny-ingress-allow-egress", "deny", false)
			}, "30s", "1s").Should(BeTrue(),
				"Deny policy must be programmed on vxlan.calico ingress on both nodes")

			By("cross-node pod traffic should be blocked by explicit deny-ingress policy on HEP on vxlan.calico")
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivity()
		})
	})
