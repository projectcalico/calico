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

package calico

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type ippoolTestCase struct {
	cidr           string
	exportDisabled bool
	ipipMode       encap.Mode
	vxlanMode      encap.Mode
}

var (
	poolsTestsV4 []ippoolTestCase = []ippoolTestCase{
		// IPv4 IPIP Encapsulation cases.
		{cidr: "10.10.0.0/16", exportDisabled: false, ipipMode: encap.Always},
		{cidr: "10.11.0.0/16", exportDisabled: true, ipipMode: encap.Always},
		{cidr: "10.12.0.0/16", exportDisabled: false, ipipMode: encap.CrossSubnet},
		{cidr: "10.13.0.0/16", exportDisabled: true, ipipMode: encap.CrossSubnet},
		// IPv4 No-Encapsulation case.
		{cidr: "10.14.0.0/16", exportDisabled: false},
		{cidr: "10.15.0.0/16", exportDisabled: true},
		// IPv4 VXLAN Encapsulation cases.
		{cidr: "10.16.0.0/16", exportDisabled: false, vxlanMode: encap.Always},
		{cidr: "10.17.0.0/16", exportDisabled: true, vxlanMode: encap.Always},
		{cidr: "10.18.0.0/16", exportDisabled: false, vxlanMode: encap.CrossSubnet},
		{cidr: "10.19.0.0/16", exportDisabled: true, vxlanMode: encap.CrossSubnet},
	}

	poolsTestsV6 []ippoolTestCase = []ippoolTestCase{
		// IPv6 IPIP Encapsulation cases.
		{cidr: "dead:beef:10::/64", exportDisabled: false, ipipMode: encap.Always},
		{cidr: "dead:beef:11::/64", exportDisabled: true, ipipMode: encap.Always},
		{cidr: "dead:beef:12::/64", exportDisabled: false, ipipMode: encap.CrossSubnet},
		{cidr: "dead:beef:13::/64", exportDisabled: true, ipipMode: encap.CrossSubnet},
		// IPv6 No-Encapsulation case.
		{cidr: "dead:beef:14::/64", exportDisabled: false},
		{cidr: "dead:beef:15::/64", exportDisabled: true},
		// IPv6 VXLAN Encapsulation cases.
		{cidr: "dead:beef:16::/64", exportDisabled: false, vxlanMode: encap.Always},
		{cidr: "dead:beef:17::/64", exportDisabled: true, vxlanMode: encap.Always},
		{cidr: "dead:beef:18::/64", exportDisabled: false, vxlanMode: encap.CrossSubnet},
		{cidr: "dead:beef:19::/64", exportDisabled: true, vxlanMode: encap.CrossSubnet},
	}
)

// Kernel-programming filter statements expected for the IPv4 pool table above, split by class of
// IP Pool and, for the classes that are configurable, by which component ends up owning the
// cluster routes.
var (
	kernelIPIPByBIRDV4 = []string{
		`  if (net ~ 10.10.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.11.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.12.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 1.1.1.0/24)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.13.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 1.1.1.0/24)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
	}
	kernelIPIPByFelixV4 = []string{
		`  if (net ~ 10.10.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.12.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
	}
	kernelNoEncapByBIRDV4 = []string{
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { accept; }`,
	}
	kernelNoEncapByFelixV4 = []string{
		`  if (net ~ 10.14.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
	}
	kernelVXLANV4 = []string{
		`  if (net ~ 10.16.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.18.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
	}

	// The pool CIDRs that the iBGP export filter rejects, for the IPv4 pool table above, grouped by
	// class of IP Pool.  A pool is in the list when Felix programs its cluster routes: this node
	// learns those routes from the kernel, but they are the owning node's to advertise.  Both the
	// CrossSubnet pools and the unencapsulated pool are here because their routes do not
	// necessarily leave via a Calico tunnel device, so the interface test alone lets them through.
	// Pools with BGP export disabled are absent: they are rejected outright, ahead of this filter.
	ibgpRejectIPIPByFelixV4 = []string{
		`  if (net ~ 10.10.0.0/16) then { reject; }`,
		`  if (net ~ 10.12.0.0/16) then { reject; }`,
	}
	ibgpRejectNoEncapByFelixV4 = []string{
		`  if (net ~ 10.14.0.0/16) then { reject; }`,
	}
	ibgpRejectVXLANV4 = []string{
		`  if (net ~ 10.16.0.0/16) then { reject; }`,
		`  if (net ~ 10.18.0.0/16) then { reject; }`,
	}

	// The filters for exporting to BGP peers only depend on DisableBGPExport, so they are the same
	// whichever component programs the cluster routes.
	exportStatementsV4 = []string{
		`  if (net ~ 10.10.0.0/16) then { accept; }`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.12.0.0/16) then { accept; }`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.16.0.0/16) then { accept; }`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.18.0.0/16) then { accept; }`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # BGP export is disabled.`,
	}
)

// The same, for the IPv6 pool table.  There is no krt_tunnel for IPv6, so a BIRD-programmed pool
// is a plain accept; and the IPv6 kernel filter only carries the reject statements, because the
// template ends with a catch-all accept.
var (
	kernelIPIPByBIRDV6 = []string{
		`  if (net ~ dead:beef:10::/64) then { accept; }`,
		`  if (net ~ dead:beef:11::/64) then { accept; }`,
		`  if (net ~ dead:beef:12::/64) then { accept; }`,
		`  if (net ~ dead:beef:13::/64) then { accept; }`,
	}
	kernelIPIPByFelixV6 = []string{
		`  if (net ~ dead:beef:10::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:11::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:12::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:13::/64) then { reject; } # Cluster routes are handled by Felix.`,
	}
	kernelNoEncapByBIRDV6 = []string{
		`  if (net ~ dead:beef:14::/64) then { accept; }`,
		`  if (net ~ dead:beef:15::/64) then { accept; }`,
	}
	kernelNoEncapByFelixV6 = []string{
		`  if (net ~ dead:beef:14::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:15::/64) then { reject; } # Cluster routes are handled by Felix.`,
	}
	kernelVXLANV6 = []string{
		`  if (net ~ dead:beef:16::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:17::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:18::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:19::/64) then { reject; } # VXLAN routes are handled by Felix.`,
	}

	// The same, for the IPv6 pool table.  IPIP is IPv4-only in practice, but processIPPool keys off
	// the pool's ipipMode rather than the IP version, so the IPv6 IPIP pools behave the same way.
	ibgpRejectIPIPByFelixV6 = []string{
		`  if (net ~ dead:beef:10::/64) then { reject; }`,
		`  if (net ~ dead:beef:12::/64) then { reject; }`,
	}
	ibgpRejectNoEncapByFelixV6 = []string{
		`  if (net ~ dead:beef:14::/64) then { reject; }`,
	}
	ibgpRejectVXLANV6 = []string{
		`  if (net ~ dead:beef:16::/64) then { reject; }`,
		`  if (net ~ dead:beef:18::/64) then { reject; }`,
	}

	exportStatementsV6 = []string{
		`  if (net ~ dead:beef:10::/64) then { accept; }`,
		`  if (net ~ dead:beef:11::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:12::/64) then { accept; }`,
		`  if (net ~ dead:beef:13::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:14::/64) then { accept; }`,
		`  if (net ~ dead:beef:15::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:16::/64) then { accept; }`,
		`  if (net ~ dead:beef:17::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:18::/64) then { accept; }`,
		`  if (net ~ dead:beef:19::/64) then { reject; } # BGP export is disabled.`,
	}
)

// Test_processIPPools walks BGPConfiguration.programClusterRoutes over its whole enum, checking
// which classes of IP Pool BIRD is left programming the cluster routes for.  The default is
// EnabledNoEncapOnly: BIRD keeps the unencapsulated pools and Felix takes the IPIP ones.
func Test_processIPPools(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		programClusterRoutes *string
		ipVersion            int
		wantKernel           []string
		// wantIBGPRejectCIDRs is the pool-CIDR arm of the iBGP export reject: the pools whose
		// cluster routes Felix programs.
		wantIBGPRejectCIDRs []string
		// felixOwnsIPIP selects the interface arm of the same reject: tunl0 is only in it when
		// Felix programs the IPIP cluster routes.
		felixOwnsIPIP bool
	}{
		{
			name:                "IPv4, field unset: BIRD programs unencapsulated pools only",
			ipVersion:           4,
			wantKernel:          slices.Concat(kernelIPIPByFelixV4, kernelNoEncapByBIRDV4, kernelVXLANV4),
			wantIBGPRejectCIDRs: slices.Concat(ibgpRejectIPIPByFelixV4, ibgpRejectVXLANV4),
			felixOwnsIPIP:       true,
		},
		{
			name:                 "IPv4, EnabledNoEncapOnly: BIRD programs unencapsulated pools only",
			programClusterRoutes: ptr.To(v3.EnabledNoEncapOnly),
			ipVersion:            4,
			wantKernel:           slices.Concat(kernelIPIPByFelixV4, kernelNoEncapByBIRDV4, kernelVXLANV4),
			wantIBGPRejectCIDRs:  slices.Concat(ibgpRejectIPIPByFelixV4, ibgpRejectVXLANV4),
			felixOwnsIPIP:        true,
		},
		{
			name:                 "IPv4, Enabled: BIRD programs both IPIP and unencapsulated pools",
			programClusterRoutes: ptr.To(v3.Enabled),
			ipVersion:            4,
			wantKernel:           slices.Concat(kernelIPIPByBIRDV4, kernelNoEncapByBIRDV4, kernelVXLANV4),
			wantIBGPRejectCIDRs:  slices.Clone(ibgpRejectVXLANV4),
			felixOwnsIPIP:        false,
		},
		{
			name:                 "IPv4, EnabledIPIPOnly: BIRD programs IPIP pools only",
			programClusterRoutes: ptr.To(v3.EnabledIPIPOnly),
			ipVersion:            4,
			wantKernel:           slices.Concat(kernelIPIPByBIRDV4, kernelNoEncapByFelixV4, kernelVXLANV4),
			wantIBGPRejectCIDRs:  slices.Concat(ibgpRejectNoEncapByFelixV4, ibgpRejectVXLANV4),
			felixOwnsIPIP:        false,
		},
		{
			name:                 "IPv4, Disabled: Felix programs everything",
			programClusterRoutes: ptr.To(v3.Disabled),
			ipVersion:            4,
			wantKernel:           slices.Concat(kernelIPIPByFelixV4, kernelNoEncapByFelixV4, kernelVXLANV4),
			wantIBGPRejectCIDRs:  slices.Concat(ibgpRejectIPIPByFelixV4, ibgpRejectNoEncapByFelixV4, ibgpRejectVXLANV4),
			felixOwnsIPIP:        true,
		},
		{
			name:                 "IPv4, unrecognised value: falls back to the default",
			programClusterRoutes: ptr.To("SomethingFromANewerAPI"),
			ipVersion:            4,
			wantKernel:           slices.Concat(kernelIPIPByFelixV4, kernelNoEncapByBIRDV4, kernelVXLANV4),
			wantIBGPRejectCIDRs:  slices.Concat(ibgpRejectIPIPByFelixV4, ibgpRejectVXLANV4),
			felixOwnsIPIP:        true,
		},
		{
			name:                "IPv6, field unset: BIRD programs unencapsulated pools only",
			ipVersion:           6,
			wantKernel:          slices.Concat(kernelIPIPByFelixV6, kernelNoEncapByBIRDV6, kernelVXLANV6),
			wantIBGPRejectCIDRs: slices.Concat(ibgpRejectIPIPByFelixV6, ibgpRejectVXLANV6),
			felixOwnsIPIP:       true,
		},
		{
			name:                 "IPv6, Enabled: BIRD programs both IPIP and unencapsulated pools",
			programClusterRoutes: ptr.To(v3.Enabled),
			ipVersion:            6,
			wantKernel:           slices.Concat(kernelIPIPByBIRDV6, kernelNoEncapByBIRDV6, kernelVXLANV6),
			wantIBGPRejectCIDRs:  slices.Clone(ibgpRejectVXLANV6),
			felixOwnsIPIP:        false,
		},
		{
			name:                 "IPv6, Disabled: Felix programs everything",
			programClusterRoutes: ptr.To(v3.Disabled),
			ipVersion:            6,
			wantKernel:           slices.Concat(kernelIPIPByFelixV6, kernelNoEncapByFelixV6, kernelVXLANV6),
			wantIBGPRejectCIDRs:  slices.Concat(ibgpRejectIPIPByFelixV6, ibgpRejectNoEncapByFelixV6, ibgpRejectVXLANV6),
			felixOwnsIPIP:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalNodeName := NodeName
			NodeName = "test-node-ippools"
			t.Cleanup(func() {
				NodeName = originalNodeName
				_ = os.Unsetenv("CALICO_ROUTER_ID")
			})

			pools, exportStatements := poolsTestsV4, exportStatementsV4
			if tc.ipVersion == 6 {
				pools, exportStatements = poolsTestsV6, exportStatementsV6
			}

			cache := ippoolTestCasesToKVPairs(t, pools, tc.ipVersion)
			if tc.ipVersion == 4 {
				// The local subnet is needed to render the ipipMode: CrossSubnet statements.
				cache[fmt.Sprintf("/calico/bgp/v1/host/%s/network_v4", NodeName)] = "1.1.1.0/24"
			}

			c := newTestClient(cache, nil)
			if tc.programClusterRoutes != nil {
				c.globalBGPConfig = &v3.BGPConfiguration{
					Spec: v3.BGPConfigurationSpec{
						ProgramClusterRoutes: tc.programClusterRoutes,
					},
				}
			}
			config := &types.BirdBGPConfig{NodeName: NodeName}

			require.NoError(t, c.processIPPools(c.getBGPProcessorContext(), config, tc.ipVersion))

			wantKernel := slices.Clone(tc.wantKernel)
			slices.Sort(wantKernel)
			if tc.ipVersion == 6 {
				wantKernel = filterExpectedStatements(wantKernel, "reject")
			}
			require.Equal(t, wantKernel, config.KernelFilterForIPPools)

			wantExport := slices.Clone(exportStatements)
			slices.Sort(wantExport)
			require.Equal(t, filterExpectedStatements(wantExport, "reject"), config.BGPExportFilterForDisabledIPPools)
			require.Equal(t, filterExpectedStatements(wantExport, "accept"), config.BGPExportFilterForEnabledIPPools)

			require.Equal(t,
				wantIBGPExportReject(tc.felixOwnsIPIP, tc.wantIBGPRejectCIDRs),
				config.IBGPExportFilterForFelixClusterRoutes)
		})
	}
}

// wantIBGPExportReject spells out the whole reject that confd builds for internal peers: the
// interface arm, whose tunl0 test is only present when Felix programs the IPIP cluster routes,
// followed by the pool-CIDR arm for the pools Felix owns.  The text is written out here rather
// than borrowed from the code under test, so that a change to what BIRD is asked to match has to
// be made deliberately in both places.
func wantIBGPExportReject(felixOwnsIPIP bool, rejectCIDRs []string) []string {
	interfaces := `(ifname ~ "*.cali") || (ifname ~ "*.calico")`
	if felixOwnsIPIP {
		interfaces += ` || (ifname ~ "tunl0")`
	}
	lines := []string{
		"if (defined(ifname)) then {",
		"  if (" + interfaces + ") then {",
		"    reject;",
		"  }",
		"}",
	}
	if len(rejectCIDRs) == 0 {
		return lines
	}
	lines = append(lines,
		"if (defined(source) && (source = RTS_INHERIT) && ((dest = RTD_ROUTER) || (dest = RTD_MULTIPATH))) then {",
		"  # Cluster routes for these pools are Felix's to program, and the owning node's to advertise.",
	)
	sortedCIDRs := slices.Clone(rejectCIDRs)
	slices.Sort(sortedCIDRs)
	lines = append(lines, sortedCIDRs...)
	return append(lines, "}")
}

func Test_processIPPoolsV4_NoLocalSubnet(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node-ippools"
	defer func() {
		NodeName = originalNodeName
		_ = os.Unsetenv("CALICO_ROUTER_ID")
	}()

	cache := ippoolTestCasesToKVPairs(t, poolsTestsV4, 4)

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.processIPPools(c.getBGPProcessorContext(), config, 4)
	require.NoError(t, err)

	if config.KernelFilterForIPPools != nil {
		t.Errorf("Expected BIRD filter for programming kernel to be nil")
	}

	expected := slices.Clone(exportStatementsV4)
	slices.Sort(expected)
	require.Equal(t, filterExpectedStatements(expected, "reject"), config.BGPExportFilterForDisabledIPPools)
	require.Equal(t, filterExpectedStatements(expected, "accept"), config.BGPExportFilterForEnabledIPPools)
}

func Test_processWireguardPeerFilterV4(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "local-node"
	defer func() {
		NodeName = originalNodeName
	}()

	cache := map[string]string{
		"/calico/bgp/v1/host/local-node/ip_addr_v4":        "10.0.0.1",
		"/calico/bgp/v1/host/local-node/wireguard_addr_v4": "192.168.1.1",

		"/calico/bgp/v1/host/remote-wg/ip_addr_v4":        "10.0.0.2",
		"/calico/bgp/v1/host/remote-wg/wireguard_addr_v4": "192.168.1.2",

		"/calico/bgp/v1/host/remote-nowg/ip_addr_v4": "10.0.0.3",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{NodeName: NodeName}

	c.processWireguardPeerFilter(config, 4)

	expected := []string{
		`  if (defined(bgp_next_hop) && bgp_next_hop = 10.0.0.2) then { reject; } # WireGuard routes handled by Felix.`,
	}

	if !reflect.DeepEqual(config.WireguardPeerKernelFilter, expected) {
		t.Errorf("WireguardPeerKernelFilter mismatch:\n  got:  %#v\n  want: %#v",
			config.WireguardPeerKernelFilter, expected)
	}
}

func Test_processWireguardPeerFilterV6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "local-node"
	defer func() {
		NodeName = originalNodeName
	}()

	cache := map[string]string{
		"/calico/bgp/v1/host/local-node/ip_addr_v6":        "fd00::1",
		"/calico/bgp/v1/host/local-node/wireguard_addr_v6": "fd01::1",

		"/calico/bgp/v1/host/remote-wg/ip_addr_v6":        "fd00::2",
		"/calico/bgp/v1/host/remote-wg/wireguard_addr_v6": "fd01::2",

		"/calico/bgp/v1/host/remote-nowg/ip_addr_v6": "fd00::3",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{NodeName: NodeName}

	c.processWireguardPeerFilter(config, 6)

	expected := []string{
		`  if (defined(bgp_next_hop) && bgp_next_hop = fd00::2) then { reject; } # WireGuard routes handled by Felix.`,
	}

	if !reflect.DeepEqual(config.WireguardPeerKernelFilter, expected) {
		t.Errorf("WireguardPeerKernelFilter mismatch:\n  got:  %#v\n  want: %#v",
			config.WireguardPeerKernelFilter, expected)
	}
}

func Test_processWireguardPeerFilter_NoWireguard(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "local-node"
	defer func() {
		NodeName = originalNodeName
	}()

	cache := map[string]string{
		"/calico/bgp/v1/host/local-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/remote-a/ip_addr_v4":   "10.0.0.2",
		"/calico/bgp/v1/host/remote-b/ip_addr_v4":   "10.0.0.3",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{NodeName: NodeName}

	c.processWireguardPeerFilter(config, 4)

	if len(config.WireguardPeerKernelFilter) != 0 {
		t.Errorf("Expected empty WireguardPeerKernelFilter, got: %#v",
			config.WireguardPeerKernelFilter)
	}
}

func Test_processWireguardPeerFilter_AllWireguard(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "local-node"
	defer func() {
		NodeName = originalNodeName
	}()

	cache := map[string]string{
		"/calico/bgp/v1/host/local-node/ip_addr_v4":        "10.0.0.1",
		"/calico/bgp/v1/host/local-node/wireguard_addr_v4": "192.168.1.1",

		"/calico/bgp/v1/host/remote-a/ip_addr_v4":        "10.0.0.2",
		"/calico/bgp/v1/host/remote-a/wireguard_addr_v4": "192.168.1.2",

		"/calico/bgp/v1/host/remote-b/ip_addr_v4":        "10.0.0.3",
		"/calico/bgp/v1/host/remote-b/wireguard_addr_v4": "192.168.1.3",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{NodeName: NodeName}

	c.processWireguardPeerFilter(config, 4)

	expected := []string{
		`  if (defined(bgp_next_hop) && bgp_next_hop = 10.0.0.2) then { reject; } # WireGuard routes handled by Felix.`,
		`  if (defined(bgp_next_hop) && bgp_next_hop = 10.0.0.3) then { reject; } # WireGuard routes handled by Felix.`,
	}
	slices.Sort(expected)

	if !reflect.DeepEqual(config.WireguardPeerKernelFilter, expected) {
		t.Errorf("WireguardPeerKernelFilter mismatch:\n  got:  %#v\n  want: %#v",
			config.WireguardPeerKernelFilter, expected)
	}
}

// Test_processWireguardPeerFilter_LocalNoWireguard covers a mixed cluster where
// the local node isn't running WireGuard but a remote peer is. The local node
// routes to that peer over the normal BGP path, so we must not reject BIRD's
// kernel route for it.
func Test_processWireguardPeerFilter_LocalNoWireguard(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "local-node"
	defer func() {
		NodeName = originalNodeName
	}()

	cache := map[string]string{
		"/calico/bgp/v1/host/local-node/ip_addr_v4": "10.0.0.1",

		"/calico/bgp/v1/host/remote-wg/ip_addr_v4":        "10.0.0.2",
		"/calico/bgp/v1/host/remote-wg/wireguard_addr_v4": "192.168.1.2",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{NodeName: NodeName}

	c.processWireguardPeerFilter(config, 4)

	if len(config.WireguardPeerKernelFilter) != 0 {
		t.Errorf("Expected empty WireguardPeerKernelFilter, got: %#v",
			config.WireguardPeerKernelFilter)
	}
}

func ippoolTestCasesToKVPairs(t *testing.T, tcs []ippoolTestCase, ipVersion int) map[string]string {
	cache := map[string]string{}
	for _, tc := range tcs {
		ippool := ippoolForTestCase(tc)
		jsonIPPool, err := json.Marshal(*ippool)
		if err != nil {
			t.Errorf("Error formatting IPPool into JSON: %s", err)
		}

		name := strings.Replace(ippool.CIDR.String(), "/", "-", 1)
		key := fmt.Sprintf("/calico/v1/ipam/v%d/pool/%s", ipVersion, name)
		cache[key] = string(jsonIPPool)

	}
	return cache
}

func ippoolForTestCase(tc ippoolTestCase) *model.IPPool {
	ippool := model.IPPool{}
	ippool.CIDR = net.MustParseCIDR(tc.cidr)
	ippool.IPIPMode = tc.ipipMode
	ippool.VXLANMode = tc.vxlanMode
	ippool.DisableBGPExport = tc.exportDisabled
	return &ippool
}

func filterExpectedStatements(statements []string, filterAction string) (filtered []string) {
	if len(filterAction) == 0 {
		return statements
	}
	for _, s := range statements {
		if strings.Contains(s, fmt.Sprintf("%s; }", filterAction)) {
			filtered = append(filtered, s)
		}
	}
	return
}
