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

func Test_processIPPoolsV4(t *testing.T) {
	forKernelStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.11.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.12.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 1.1.1.0/24)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
		`  if (net ~ 10.13.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 1.1.1.0/24)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { accept; }`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.18.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
	}
	slices.Sort(forKernelStatements)

	forExportStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { accept; }`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.12.0.0/16) then { accept; }`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { accept; }`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.18.0.0/16) then { accept; }`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # BGP export is disabled.`,
	}
	slices.Sort(forExportStatements)

	originalNodeName := NodeName
	NodeName = "test-node-ippools"
	defer func() {
		NodeName = originalNodeName
		_ = os.Unsetenv("CALICO_ROUTER_ID")
	}()

	cache := ippoolTestCasesToKVPairs(t, poolsTestsV4, 4)
	key := fmt.Sprintf("/calico/bgp/v1/host/%s/network_v4", NodeName)
	cache[key] = "1.1.1.0/24"

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.processIPPools(config, 4)
	require.NoError(t, err)

	if !reflect.DeepEqual(config.KernelFilterForIPPools, forKernelStatements) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.KernelFilterForIPPools, forKernelStatements)
	}

	expected := filterExpectedStatements(forExportStatements, "reject")
	if !reflect.DeepEqual(config.BGPExportFilterForDisabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForDisabledIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "accept")
	if !reflect.DeepEqual(config.BGPExportFilterForEnabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForEnabledIPPools, expected)
	}
}

func Test_processIPPoolsV4_NoLocalSubnet(t *testing.T) {
	forExportStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { accept; }`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.12.0.0/16) then { accept; }`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { accept; }`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.18.0.0/16) then { accept; }`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # BGP export is disabled.`,
	}
	slices.Sort(forExportStatements)

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

	err := c.processIPPools(config, 4)
	require.NoError(t, err)

	if config.KernelFilterForIPPools != nil {
		t.Errorf("Expected BIRD filter for programming kernel to be nil")
	}

	expected := filterExpectedStatements(forExportStatements, "reject")
	if !reflect.DeepEqual(config.BGPExportFilterForDisabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForDisabledIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "accept")
	if !reflect.DeepEqual(config.BGPExportFilterForEnabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForEnabledIPPools, expected)
	}
}

func Test_processIPPoolsV6(t *testing.T) {
	forKernelStatements := []string{
		// IPv6 IPIP Encapsulation cases.
		`  if (net ~ dead:beef:10::/64) then { accept; }`,
		`  if (net ~ dead:beef:11::/64) then { accept; }`,
		`  if (net ~ dead:beef:12::/64) then { accept; }`,
		`  if (net ~ dead:beef:13::/64) then { accept; }`,
		// IPv6 No-Encapsulation case.
		`  if (net ~ dead:beef:14::/64) then { accept; }`,
		`  if (net ~ dead:beef:15::/64) then { accept; }`,
		// IPv6 VXLAN Encapsulation cases.
		`  if (net ~ dead:beef:16::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:17::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:18::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:19::/64) then { reject; } # VXLAN routes are handled by Felix.`,
	}
	slices.Sort(forKernelStatements)

	forExportStatements := []string{
		// IPv6 IPIP Encapsulation cases.
		`  if (net ~ dead:beef:10::/64) then { accept; }`,
		`  if (net ~ dead:beef:11::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:12::/64) then { accept; }`,
		`  if (net ~ dead:beef:13::/64) then { reject; } # BGP export is disabled.`,
		// IPv6 No-Encapsulation case.
		`  if (net ~ dead:beef:14::/64) then { accept; }`,
		`  if (net ~ dead:beef:15::/64) then { reject; } # BGP export is disabled.`,
		// IPv6 VXLAN Encapsulation cases.
		`  if (net ~ dead:beef:16::/64) then { accept; }`,
		`  if (net ~ dead:beef:17::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:18::/64) then { accept; }`,
		`  if (net ~ dead:beef:19::/64) then { reject; } # BGP export is disabled.`,
	}
	slices.Sort(forExportStatements)

	originalNodeName := NodeName
	NodeName = "test-node-ippools"
	defer func() {
		NodeName = originalNodeName
		_ = os.Unsetenv("CALICO_ROUTER_ID")
	}()

	cache := ippoolTestCasesToKVPairs(t, poolsTestsV6, 6)

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.processIPPools(config, 6)
	require.NoError(t, err)

	expected := filterExpectedStatements(forKernelStatements, "reject")
	if !reflect.DeepEqual(config.KernelFilterForIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.KernelFilterForIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "reject")
	if !reflect.DeepEqual(config.BGPExportFilterForDisabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForDisabledIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "accept")
	if !reflect.DeepEqual(config.BGPExportFilterForEnabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForEnabledIPPools, expected)
	}
}

func Test_processIPPoolsV4_FelixProgramsClusterRoutes(t *testing.T) {
	forKernelStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.12.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # Cluster routes are handled by Felix.`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.18.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
	}
	slices.Sort(forKernelStatements)

	forExportStatements := []string{
		// IPv4 IPIP Encapsulation cases.
		`  if (net ~ 10.10.0.0/16) then { accept; }`,
		`  if (net ~ 10.11.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.12.0.0/16) then { accept; }`,
		`  if (net ~ 10.13.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 No-Encapsulation case.
		`  if (net ~ 10.14.0.0/16) then { accept; }`,
		`  if (net ~ 10.15.0.0/16) then { reject; } # BGP export is disabled.`,
		// IPv4 VXLAN Encapsulation cases.
		`  if (net ~ 10.16.0.0/16) then { accept; }`,
		`  if (net ~ 10.17.0.0/16) then { reject; } # BGP export is disabled.`,
		`  if (net ~ 10.18.0.0/16) then { accept; }`,
		`  if (net ~ 10.19.0.0/16) then { reject; } # BGP export is disabled.`,
	}
	slices.Sort(forExportStatements)

	originalNodeName := NodeName
	NodeName = "test-node-ippools"
	defer func() {
		NodeName = originalNodeName
		_ = os.Unsetenv("CALICO_ROUTER_ID")
	}()

	cache := ippoolTestCasesToKVPairs(t, poolsTestsV4, 4)
	cache[fmt.Sprintf("/calico/bgp/v1/host/%s/network_v4", NodeName)] = "1.1.1.0/24"

	c := newTestClient(cache, nil)
	programClusterRoutes := "Disabled"
	c.bgpConfigs[globalConfigName] = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: &programClusterRoutes,
		},
	}
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.processIPPools(config, 4)
	require.NoError(t, err)

	if !reflect.DeepEqual(config.KernelFilterForIPPools, forKernelStatements) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.KernelFilterForIPPools, forKernelStatements)
	}

	expected := filterExpectedStatements(forExportStatements, "reject")
	if !reflect.DeepEqual(config.BGPExportFilterForDisabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForDisabledIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "accept")
	if !reflect.DeepEqual(config.BGPExportFilterForEnabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForEnabledIPPools, expected)
	}
}

func Test_processIPPoolsV6_FelixProgramsClusterRoutes(t *testing.T) {
	forKernelStatements := []string{
		// IPv6 IPIP Encapsulation cases.
		`  if (net ~ dead:beef:10::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:11::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:12::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:13::/64) then { reject; } # Cluster routes are handled by Felix.`,
		// IPv6 No-Encapsulation case.
		`  if (net ~ dead:beef:14::/64) then { reject; } # Cluster routes are handled by Felix.`,
		`  if (net ~ dead:beef:15::/64) then { reject; } # Cluster routes are handled by Felix.`,
		// IPv6 VXLAN Encapsulation cases.
		`  if (net ~ dead:beef:16::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:17::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:18::/64) then { reject; } # VXLAN routes are handled by Felix.`,
		`  if (net ~ dead:beef:19::/64) then { reject; } # VXLAN routes are handled by Felix.`,
	}
	slices.Sort(forKernelStatements)

	forExportStatements := []string{
		// IPv6 IPIP Encapsulation cases.
		`  if (net ~ dead:beef:10::/64) then { accept; }`,
		`  if (net ~ dead:beef:11::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:12::/64) then { accept; }`,
		`  if (net ~ dead:beef:13::/64) then { reject; } # BGP export is disabled.`,
		// IPv6 No-Encapsulation case.
		`  if (net ~ dead:beef:14::/64) then { accept; }`,
		`  if (net ~ dead:beef:15::/64) then { reject; } # BGP export is disabled.`,
		// IPv6 VXLAN Encapsulation cases.
		`  if (net ~ dead:beef:16::/64) then { accept; }`,
		`  if (net ~ dead:beef:17::/64) then { reject; } # BGP export is disabled.`,
		`  if (net ~ dead:beef:18::/64) then { accept; }`,
		`  if (net ~ dead:beef:19::/64) then { reject; } # BGP export is disabled.`,
	}
	slices.Sort(forExportStatements)

	originalNodeName := NodeName
	NodeName = "test-node-ippools"
	defer func() {
		NodeName = originalNodeName
		_ = os.Unsetenv("CALICO_ROUTER_ID")
	}()

	cache := ippoolTestCasesToKVPairs(t, poolsTestsV6, 6)

	c := newTestClient(cache, nil)
	programClusterRoutes := "Disabled"
	c.bgpConfigs[globalConfigName] = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: &programClusterRoutes,
		},
	}
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.processIPPools(config, 6)
	require.NoError(t, err)

	expected := filterExpectedStatements(forKernelStatements, "reject")
	if !reflect.DeepEqual(config.KernelFilterForIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.KernelFilterForIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "reject")
	if !reflect.DeepEqual(config.BGPExportFilterForDisabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForDisabledIPPools, expected)
	}

	expected = filterExpectedStatements(forExportStatements, "accept")
	if !reflect.DeepEqual(config.BGPExportFilterForEnabledIPPools, expected) {
		t.Errorf("Generated BIRD config differs from expectation:\n Generated=%#v,\n Expected=%#v",
			config.BGPExportFilterForEnabledIPPools, expected)
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

// programClusterRoutesCacheKey is the confd cache key that mirrors
// BGPConfiguration.Spec.ProgramClusterRoutes into BIRD config.
const programClusterRoutesCacheKey = "/calico/bgp/v1/global/program_cluster_routes"

func strPtr(s string) *string { return &s }

func TestGetProgramClusterRoutesKVPair(t *testing.T) {
	// Initially, set ProgramClusterRoutes to Enabled.
	c := newTestClient(make(map[string]string), nil)
	res := &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Enabled"),
		},
	}
	c.getProgramClusterRoutesKVPair(res, model.GlobalBGPConfigKey{})
	require.Equal(t, "Enabled", c.cache[programClusterRoutesCacheKey])

	// Switch ProgramClusterRoutes to Disabled.
	res = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Disabled"),
		},
	}
	c.getProgramClusterRoutesKVPair(res, model.GlobalBGPConfigKey{})
	require.Equal(t, "Disabled", c.cache[programClusterRoutesCacheKey])

	// Switch ProgramClusterRoutes to Enabled.
	res = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Enabled"),
		},
	}
	c.getProgramClusterRoutesKVPair(res, model.GlobalBGPConfigKey{})
	require.Equal(t, "Enabled", c.cache[programClusterRoutesCacheKey])

	// Unsetting ProgramClusterRoutes.
	res = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: nil,
		},
	}
	c.getProgramClusterRoutesKVPair(res, model.GlobalBGPConfigKey{})
	require.NotContains(t, c.cache, programClusterRoutesCacheKey)
}

func TestGetProgramClusterRoutesKVPair_NilResourceDeletesCacheEntry(t *testing.T) {
	c := newTestClient(map[string]string{
		programClusterRoutesCacheKey: "Disabled",
	}, nil)
	c.getProgramClusterRoutesKVPair(nil, model.GlobalBGPConfigKey{})
	require.NotContains(t, c.cache, programClusterRoutesCacheKey)
}

// ProgramClusterRoutes is intentionally wired as global-only in
// updateBGPConfigCache (client.go): the per-node branch does not call
// getProgramClusterRoutesKVPair. This test pins that behavior — if per-node
// support is ever added, this test should be updated along with the call site.
func TestGetProgramClusterRoutesKVPair_PerNodeKeyDoesNotWriteGlobal(t *testing.T) {
	c := newTestClient(make(map[string]string), nil)
	res := &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Enabled"),
		},
	}
	c.getProgramClusterRoutesKVPair(res, model.NodeBGPConfigKey{Nodename: "nodeX"})
	require.NotContains(t, c.cache, programClusterRoutesCacheKey)
}

func TestUpdateBGPConfigCache_ProgramClusterRoutes_UpdateThenDelete(t *testing.T) {
	c := newTestClient(make(map[string]string), nil)
	var (
		svcAdvertisement bool
		updatePeersV1    bool
		updateReasons    []string
	)

	// First: set ProgramClusterRoutes=Disabled and confirm cache is populated
	// via the full updateBGPConfigCache entrypoint (exercises wiring at
	// client.go's global branch).
	res := &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Disabled"),
		},
	}
	c.updateBGPConfigCache("default", res, &svcAdvertisement, &updatePeersV1, &updateReasons)
	require.Equal(t, "Disabled", c.cache[programClusterRoutesCacheKey])

	// Second: set ProgramClusterRoutes=Enabled and confirm cache is populated
	// via the full updateBGPConfigCache entrypoint (exercises wiring at
	// client.go's global branch).
	res = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Enabled"),
		},
	}
	c.updateBGPConfigCache("default", res, &svcAdvertisement, &updatePeersV1, &updateReasons)
	require.Equal(t, "Enabled", c.cache[programClusterRoutesCacheKey])

	// Finally: clear the field and confirm the cache entry is removed.
	res = &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: nil,
		},
	}
	c.updateBGPConfigCache("default", res, &svcAdvertisement, &updatePeersV1, &updateReasons)
	require.NotContains(t, c.cache, programClusterRoutesCacheKey)
}

func TestUpdateBGPConfigCache_ProgramClusterRoutes_PerNodeResourceNameSkipsGlobalKey(t *testing.T) {
	c := newTestClient(make(map[string]string), nil)
	var (
		svcAdvertisement bool
		updatePeersV1    bool
		updateReasons    []string
	)

	res := &v3.BGPConfiguration{
		Spec: v3.BGPConfigurationSpec{
			ProgramClusterRoutes: strPtr("Enabled"),
		},
	}
	c.updateBGPConfigCache("node.nodeX", res, &svcAdvertisement, &updatePeersV1, &updateReasons)
	require.NotContains(t, c.cache, programClusterRoutesCacheKey)
}
