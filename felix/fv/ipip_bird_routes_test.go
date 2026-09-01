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
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

// When Felix, rather than confd and BIRD, programs the cluster routes for IPIP IP Pools, BIRD's
// routes via the IPIP device are inside Felix's ownership boundary.  These tests inject the routes
// BIRD would have left behind -- its kernel protocol runs with `persist`, so it deliberately
// leaves them in the kernel when it exits -- and check what Felix does with them.
//
// There is no real BIRD in the FV topology, so the routes are injected directly.  That makes these
// tests about the ownership rule itself; what an upgrade actually does is covered by the node ST.
const (
	// Destinations outside the cluster's IP pool, so Felix never wants a route to either.  They
	// stand in for a block that BIRD had a route to and that has since been released.
	birdStrayCIDR      = "10.99.99.0/26"
	birdThirdPartyCIDR = "10.99.98.0/26"

	// RTPROT_BIRD, which `ip route` renders as "bird".
	birdRouteProto = "bird"
)

// ipipBIRDRouteTopology returns topology options for an IPIP-Always cluster, with either Felix or
// BIRD as the configured owner of the IPIP cluster routes.
//
// Ownership is selected with SimulateBIRDRoutes rather than by setting FELIX_ProgramClusterRoutes
// directly: StartNNodeTopology derives that environment variable from SimulateBIRDRoutes itself,
// after the caller's options have been built, so setting it here would be silently overwritten.
func ipipBIRDRouteTopology(birdOwnsClusterRoutes bool) infrastructure.TopologyOptions {
	// WorkloadIPs rather than CalicoIPAM as the route source: with CalicoIPAM, Felix's remote
	// routes come from IPAM blocks, and creating a workload endpoint does not allocate one.  The
	// tests here only need Felix to have some route of its own via the IPIP device.
	opts := createIPIPBaseTopologyOptions(api.IPIPModeAlways, false, "WorkloadIPs", false)
	opts.SimulateBIRDRoutes = birdOwnsClusterRoutes
	// Felix picks up routes that something else changed on its periodic resync: the interface
	// monitor's netlink subscription only feeds address tracking.  The default of 90s would make
	// these tests very slow.
	opts.ExtraEnvVars["FELIX_ROUTEREFRESHINTERVAL"] = "1"
	return opts
}

var _ = infrastructure.DatastoreDescribe(
	"IPIP cluster routes: BIRD's routes via tunl0, with Felix as the configured owner",
	// Skipping k8s: this is about kernel route ownership, not about the datastore.
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra   infrastructure.DatastoreInfra
			tc      infrastructure.TopologyContainers
			felixes []*infrastructure.Felix
			w       [2]*workload.Workload
		)

		// tunl0Routes returns felixes[0]'s routes via the IPIP device.
		tunl0Routes := func() string {
			out, err := felixes[0].ExecOutput("ip", "route", "show", "dev", dataplanedefs.IPIPIfaceName)
			if err != nil {
				return fmt.Sprintf("ERROR: %v", err)
			}
			return out
		}

		BeforeEach(func() {
			infra = getInfra()
			tc, _ = infrastructure.StartNNodeTopology(2, ipipBIRDRouteTopology(false), infra)
			felixes = tc.Felixes

			// A workload on each node, so that each node has a remote block to route to and
			// Felix has an IPIP route of its own to defend.
			for i := range w {
				w[i] = workload.Run(
					felixes[i],
					fmt.Sprintf("w%d", i),
					"default",
					fmt.Sprintf("10.65.%d.2", i),
					"8055",
					"tcp",
				)
				w[i].ConfigureInInfra(infra)
			}
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				for _, felix := range felixes {
					felix.Exec("ip", "route")
					felix.Exec("ip", "link")
				}
			}
			for _, wl := range w {
				wl.Stop()
			}
			tc.Stop()
			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		// Note: this one passes with or without the ownership rule -- Felix ignores routes it does
		// not own, so it reads the destination as unoccupied and replaces it either way.  It is
		// here as a regression guard on that atomic takeover, not as coverage of the rule.
		It("should take back a route to a destination it wants", func() {
			// Find the route Felix has programmed to the other node's block.
			felixRoute := regexp.MustCompile(`(?m)^(\S+) via (\S+) .*proto 80`)
			var match []string
			Eventually(func() []string {
				match = felixRoute.FindStringSubmatch(tunl0Routes())
				return match
			}, "60s", "500ms").Should(HaveLen(3),
				"Felix did not program an IPIP route to the remote block")
			dest, gw := match[1], match[2]

			// Stand in for the route the old BIRD left behind for the same destination: same
			// next hop and device, but BIRD's protocol.
			felixes[0].Exec("ip", "route", "replace", dest, "via", gw,
				"dev", dataplanedefs.IPIPIfaceName, "onlink", "proto", birdRouteProto)

			// Felix owns it, so it takes it back.  It must end up replaced rather than simply
			// removed: this is a destination the cluster needs a route to.
			Eventually(tunl0Routes, "30s", "500ms").Should(MatchRegexp(
				`(?m)^`+regexp.QuoteMeta(dest)+` via `+regexp.QuoteMeta(gw)+` .*proto 80`),
				"Felix did not take its route back from BIRD's protocol")
		})

		// This is the one that exercises the ownership rule: it is the only case the rule changes.
		It("should remove a route to a destination it does not want", func() {
			// A block BIRD had a route to, since released, so Felix has no route of its own to
			// replace it with.  Without the ownership rule nothing would ever clean this up.
			felixes[0].Exec("ip", "route", "add", birdStrayCIDR, "via", felixes[1].IP,
				"dev", dataplanedefs.IPIPIfaceName, "onlink", "proto", birdRouteProto)

			// Nothing asserts the route landed first: Felix's resync can remove it before a
			// check could read it back, and Exec fails the test if the add does.
			Eventually(tunl0Routes, "30s", "500ms").ShouldNot(ContainSubstring(birdStrayCIDR),
				"Felix did not remove BIRD's stale route")
		})

		It("should leave a route belonging to neither component alone", func() {
			// The rule claims BIRD's protocol only.  Felix owns the IPIP device itself, but a
			// route through it from some other source is not Felix's to delete.
			felixes[0].Exec("ip", "route", "add", birdThirdPartyCIDR, "via", felixes[1].IP,
				"dev", dataplanedefs.IPIPIfaceName, "onlink", "proto", "static")

			Consistently(tunl0Routes, "10s", "1s").Should(ContainSubstring(birdThirdPartyCIDR),
				"Felix removed a route belonging to neither Felix nor BIRD")
		})
	},
)

var _ = infrastructure.DatastoreDescribe(
	"IPIP cluster routes: BIRD's routes via tunl0, with BIRD as the configured owner",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra   infrastructure.DatastoreInfra
			tc      infrastructure.TopologyContainers
			felixes []*infrastructure.Felix
		)

		BeforeEach(func() {
			infra = getInfra()
			// Leaves the IPIP cluster routes to confd and BIRD.
			tc, _ = infrastructure.StartNNodeTopology(2, ipipBIRDRouteTopology(true), infra)
			felixes = tc.Felixes
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				for _, felix := range felixes {
					felix.Exec("ip", "route")
				}
			}
			tc.Stop()
			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		It("should leave BIRD's routes alone", func() {
			// The mirror image of the tests above, and the reason the rule is conditional: when
			// BIRD is the configured owner, its routes are not Felix's to touch.  This also
			// covers the wiring from the configuration parameter through to the policy, which
			// the unit tests cannot reach.
			felixes[0].Exec("ip", "route", "add", birdStrayCIDR, "via", felixes[1].IP,
				"dev", dataplanedefs.IPIPIfaceName, "onlink", "proto", birdRouteProto)

			routes := func() string {
				out, err := felixes[0].ExecOutput("ip", "route", "show", "dev", dataplanedefs.IPIPIfaceName)
				if err != nil {
					return fmt.Sprintf("ERROR: %v", err)
				}
				return out
			}
			Consistently(routes, "10s", "1s").Should(ContainSubstring(birdStrayCIDR),
				"Felix removed BIRD's route even though BIRD is the configured owner")
		})
	},
)
