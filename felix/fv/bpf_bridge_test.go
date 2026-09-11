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
	"encoding/json"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

// These tests cover a host data interface (the node's own eth0) that is enslaved
// to a Linux bridge. The host's L3 (IP, routes) lives on the bridge or one of its
// VLAN sub-interfaces, so the BPF host-endpoint program must land there and not on
// the enslaved port. With the program wrongly on the port, BPF reverse-path
// enforcement keys off the port's ingress ifindex while the return route resolves
// via the L3 device; under BPFEnforceRPF=Strict that mismatch drops otherwise-valid
// inbound traffic (including the node's own datastore/return traffic). Running with
// Strict RPF therefore makes the connectivity check a real regression guard.
//
// All of the bridge rewiring is done while Felix is held back (DelayFelixStart), so
// Felix sees the final topology on its first interface scan rather than having the
// node's main interface reconfigured underneath a running Felix.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bridge-enslaved host interface",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

		if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
			// Non-BPF run.
			return
		}

		var (
			infra   infrastructure.DatastoreInfra
			tc      infrastructure.TopologyContainers
			options infrastructure.TopologyOptions
			felix   *infrastructure.Felix
		)

		BeforeEach(func() {
			infra = getInfra()
			options = infrastructure.DefaultTopologyOptions()
			options.DelayFelixStart = true
			// Enforce strict RPF so that attaching the program to the wrong
			// device (the bridge port) would drop the node's inbound traffic.
			options.ExtraEnvVars["FELIX_BPFEnforceRPF"] = "Strict"
		})

		getBPFNet := func() []string {
			out, _ := felix.ExecOutput("bpftool", "-jp", "net")
			devs := []string{}
			var output []struct {
				Tc []struct {
					Devname string `json:"devname"`
				} `json:"tc"`
			}
			if err := json.Unmarshal([]byte(out), &output); err == nil && len(output) > 0 {
				for _, t := range output[0].Tc {
					devs = append(devs, t.Devname)
				}
			}
			return devs
		}

		// rewireOntoBridge enslaves eth0 to br0 and moves the host L3 (address +
		// default route) onto l3Dev, which is either br0 or a VLAN sub-interface of
		// it. It runs as a single shell invocation so the node is never left without
		// an address, and is called before Felix is started. The data iface pattern
		// is set to match the node's eth0 (so the enslaved port is classified and
		// suppressed) and the L3 device (so it gets the host-endpoint program).
		rewireOntoBridge := func(script, l3Dev, dataIfacePattern string) {
			felix.SetEnv(map[string]string{"FELIX_BPFDataIfacePattern": dataIfacePattern})

			By("Rewiring eth0 onto a bridge before Felix starts")
			felix.Exec("sh", "-ec", script)

			By("Starting Felix against the final topology")
			felix.TriggerDelayedStart()

			By("Checking the host-endpoint program is on " + l3Dev + ", not the enslaved eth0")
			Eventually(getBPFNet, "60s", "1s").Should(ContainElement(l3Dev))
			Expect(getBPFNet()).NotTo(ContainElement("eth0"))

			By("Checking the interface state flags")
			// eth0 is now an L2-only bridge port; the L3 device carries the HEP.
			ensureRightIFStateFlags(felix, ifstate.FlgIPv4Ready, ifstate.FlgBridgeSlave,
				map[string]uint32{l3Dev: ifstate.FlgIPv4Ready | ifstate.FlgHEP})

			By("Checking the host still has network")
			// Felix reaching the datastore to program the above already proves the
			// rewired uplink works under strict RPF; additionally confirm the node
			// can reach its default gateway across the bridge.
			gw, err := felix.ExecOutput("sh", "-c", "ip route show default | awk '{print $3; exit}'")
			Expect(err).NotTo(HaveOccurred())
			gw = strings.TrimSpace(gw)
			Expect(gw).NotTo(BeEmpty())
			Eventually(func() error {
				return felix.ExecMayFail("ping", "-c", "1", "-W", "2", gw)
			}, "30s", "1s").ShouldNot(HaveOccurred(), "node lost network after rewiring onto the bridge")
		}

		JustBeforeEach(func() {
			tc, _ = infrastructure.StartNNodeTopology(1, options, infra)
			felix = tc.Felixes[0]

			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should attach the program to the bridge, not the enslaved port (IP on br0)", func() {
			// eth0 -> br0, host L3 directly on br0 (untagged).
			script := `
GW=$(ip route show default | awk '{print $3; exit}')
ADDR=$(ip -o -4 addr show dev eth0 | awk '{print $4; exit}')
ip link add br0 type bridge
ip link set eth0 master br0
ip link set br0 up
ip addr flush dev eth0
ip addr add "$ADDR" dev br0
[ -n "$GW" ] && ip route replace default via "$GW" dev br0
for d in all default eth0 br0; do sysctl -w net.ipv4.conf.$d.rp_filter=0; done
`
			rewireOntoBridge(script, "br0", "^eth0$|^br0$")
		})

		It("should attach the program to the bridge VLAN sub-interface, not the enslaved port (IP on br0.100)", func() {
			// eth0 -> br0 -> br0.100, host L3 on the VLAN sub-interface. The bridge
			// is made VLAN-aware with the uplink port carrying PVID 100 untagged so
			// the node's untagged traffic is mapped to VLAN 100 and reaches br0.100,
			// preserving connectivity.
			script := `
GW=$(ip route show default | awk '{print $3; exit}')
ADDR=$(ip -o -4 addr show dev eth0 | awk '{print $4; exit}')
ip link add br0 type bridge vlan_filtering 1
ip link set eth0 master br0
ip link add link br0 name br0.100 type vlan id 100
bridge vlan add dev br0 vid 100 self
bridge vlan add dev eth0 vid 100 pvid untagged
ip link set br0 up
ip link set br0.100 up
ip addr flush dev eth0
ip addr add "$ADDR" dev br0.100
[ -n "$GW" ] && ip route replace default via "$GW" dev br0.100
for d in all default eth0 br0 br0/100; do sysctl -w net.ipv4.conf.$d.rp_filter=0 2>/dev/null || true; done
`
			rewireOntoBridge(script, "br0.100", "^eth0$|^br0\\.100$")
		})
	})
