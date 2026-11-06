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
	"fmt"
	"path"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// Moving netkit devices onto TCX is the supported way off netkit attachment,
// and is required before downgrading to a release that cannot remove netkit
// programs. These tests drive that migration and the way back.
//
// "BPF-SAFE" in the name below is load-bearing: BPF jobs run with
// GINKGO_FOCUS=BPF-SAFE, so a name without it is silently filtered out in CI
// while still running locally.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ BPF netkit attach transition",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

		// Only the netkit test group has netkit workload devices to migrate.
		// Everywhere else this registers no specs at all.
		if !BPFMode() || !infrastructure.NetkitMode() {
			return
		}

		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			felix        *infrastructure.Felix
			w            [2]*workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()
			tc, calicoClient = infrastructure.StartSingleNodeTopology(
				infrastructure.DefaultTopologyOptions(), infra)
			felix = tc.Felixes[0]

			infra.AddDefaultAllow()

			// workload.Run creates netkit pairs when NetkitMode is on.
			for i := range w {
				w[i] = workload.Run(
					felix,
					fmt.Sprintf("w%d", i),
					"default",
					fmt.Sprintf("10.65.0.%d", i+2),
					"8055",
					"tcp",
				)
				w[i].ConfigureInInfra(infra)
			}
		})

		// linkType reports the device type the CNI gave the interface, which the
		// migration must not change.
		linkType := func(iface string) string {
			out, err := felix.ExecOutput("ip", "-d", "link", "show", "dev", iface)
			Expect(err).NotTo(HaveOccurred())
			if strings.Contains(out, "netkit ") {
				return "netkit"
			}
			return "veth"
		}

		hasClsact := func(iface string) bool {
			out, err := felix.ExecOutput("tc", "qdisc", "show", "dev", iface)
			Expect(err).NotTo(HaveOccurred())
			return strings.Contains(out, "clsact")
		}

		pinExists := func(dir, iface, hook string) func() bool {
			pin := path.Join(dir, fmt.Sprintf("%s_%s", iface, hook))
			return func() bool {
				out, _ := felix.ExecOutput("sh", "-c",
					fmt.Sprintf("test -e %s && echo yes || echo no", pin))
				return strings.TrimSpace(out) == "yes"
			}
		}

		// expectDrivenBy reads the mechanism out of the dataplane rather than
		// trusting the configuration. The negative half of each assertion is the
		// point: a leftover pin means the device is driven by two dataplanes at
		// once, each with its own policy and conntrack state.
		expectDrivenBy := func(mechanism string) {
			for _, iface := range []string{w[0].InterfaceName, w[1].InterfaceName} {
				for _, hook := range []string{"ingress", "egress"} {
					Eventually(pinExists(bpfdefs.NetkitPinDir, iface, hook), "60s", "500ms").
						Should(Equal(mechanism == "netkit"),
							"netkit pin for %s %s under %s attachment", iface, hook, mechanism)
					Eventually(pinExists(bpfdefs.TcxPinDir, iface, hook), "60s", "500ms").
						Should(Equal(mechanism == "tcx"),
							"tcx pin for %s %s under %s attachment", iface, hook, mechanism)
				}
				// Only legacy TC hangs its programs off a qdisc. A stray clsact
				// would also claim the ffff: handle that bandwidth QoS needs.
				Expect(hasClsact(iface)).To(Equal(mechanism == "tc"),
					"clsact on %s under %s attachment", iface, mechanism)
				// The CNI owns the device type; only the attachment may move.
				Expect(linkType(iface)).To(Equal("netkit"), "device type of %s", iface)
			}
		}

		// setAttachType changes BPFAttachType and waits for the restart it
		// causes. BPFAttachType is not a live reconfiguration: Felix exits with
		// 129 and its supervisor restarts it, so the migration happens at start
		// of day. Allow generously for that plus a full BPF re-attach.
		setAttachType := func(target api.BPFAttachOption) {
			pid := felix.GetSinglePID("calico-felix")
			infrastructure.UpdateFelixConfiguration(calicoClient, func(cfg *api.FelixConfiguration) {
				cfg.Spec.BPFAttachType = &target
			})
			Eventually(felix.GetFelixPIDs, "60s", "500ms").ShouldNot(ContainElement(pid),
				"Felix did not restart after BPFAttachType was set to %s", target)
		}

		It("should move netkit devices onto TCX and back", func() {
			cc := &connectivity.Checker{}
			expectConnectivity := func() {
				cc.ResetExpectations()
				cc.Expect(connectivity.Some, w[0], w[1])
				cc.Expect(connectivity.Some, w[1], w[0])
				cc.CheckConnectivity()
			}

			By("defaulting to netkit attachment")
			expectDrivenBy("netkit")
			expectConnectivity()

			for _, phase := range []struct {
				target    api.BPFAttachOption
				mechanism string
			}{
				{api.BPFAttachOptionTCX, "tcx"},
				{api.BPFAttachOptionNetkit, "netkit"},
			} {
				By(fmt.Sprintf("switching BPFAttachType to %s", phase.target))
				setAttachType(phase.target)

				expectDrivenBy(phase.mechanism)
				expectConnectivity()
			}
		})

		It("should keep enforcing policy across the transition", func() {
			// Reclaiming a jump map index into the wrong allocator would leave
			// two endpoints sharing a slot, so policy has to be checked and not
			// just connectivity. Denying ingress to w1 gives a deny and an allow
			// from a single policy: w0->w1 is dropped, w1->w0 is not.
			pol := api.NewGlobalNetworkPolicy()
			pol.Name = "deny-ingress-to-w1"
			pol.Spec.Selector = w[1].NameSelector()
			pol.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			_, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			cc := &connectivity.Checker{}
			expectPolicyEnforced := func() {
				cc.ResetExpectations()
				cc.Expect(connectivity.None, w[0], w[1])
				cc.Expect(connectivity.Some, w[1], w[0])
				cc.CheckConnectivity()
			}

			By("enforcing policy under netkit attachment")
			expectDrivenBy("netkit")
			expectPolicyEnforced()

			By("enforcing policy after moving onto TCX")
			setAttachType(api.BPFAttachOptionTCX)
			expectDrivenBy("tcx")
			expectPolicyEnforced()

			By("enforcing policy after moving back to netkit")
			setAttachType(api.BPFAttachOptionNetkit)
			expectDrivenBy("netkit")
			expectPolicyEnforced()
		})
	})
