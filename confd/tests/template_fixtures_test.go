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

package tests

import "github.com/projectcalico/calico/confd/pkg/backends/types"

// Standard import filter for iBGP mesh peers (same AS).
const meshImportFilter = `krt_metric = 1024;
    if (defined(bgp_local_pref)) then {
      krt_metric = 2147483647 - bgp_local_pref;
    }
    if (krt_metric < 1024) then
      preference = 200;
    accept;`

// Standard export filter for iBGP mesh peers (same AS).
const meshExportFilter = `if (!defined(krt_metric)) then { krt_metric = 1024; }
    bgp_local_pref = 2147483647 - krt_metric;
    calico_export_to_bgp_peers(true);
    reject;`

// standardIPAMKVData returns the KV data representing the IPAM blocks used by all standard
// mesh tests. These correspond to the data in mock_data/etcd/block and mock_data/kdd/ipam_v3.yaml.
// Note: pending block affinities are excluded because the calico client filters them out.
func standardIPAMKVData() map[string]string {
	return map[string]string{
		"/ipam/v2/host/kube-master/ipv4/block/10.0.0.0-30":        `{}`,
		"/ipam/v2/host/kube-master/ipv4/block/10.1.0.0-24":        `{}`,
		"/ipam/v2/host/kube-master/ipv4/block/10.2.0.1-32":        `{}`,
		"/ipam/v2/host/kube-master/ipv4/block/192.168.221.192-26": `{}`,
		"/ipam/v2/host/kube-master/ipv4/block/192.168.221.64-26":  `{"state":"confirmed"}`,
	}
}

func meshBGPExport() templateTestCase {
	return templateTestCase{
		name:      "mesh/bgp-export",
		goldenDir: "mesh/bgp-export",
		kvData:    standardIPAMKVData(),
		configV4: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "10.192.0.2",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_10_192_0_3",
					IP:           "10.192.0.3",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
				{
					Name:         "Mesh_10_192_0_4",
					IP:           "10.192.0.4",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForDisabledIPPools: []string{
				`  if (net ~ 192.168.2.0/24) then { reject; } # BGP export is disabled.`,
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 192.168.1.0/24) then { accept; }`,
				`  if (net ~ 192.168.3.0/24) then { accept; }`,
			},
			KernelFilterForIPPools: []string{
				`  if (net ~ 192.168.1.0/24) then { krt_tunnel=""; accept; }`,
				`  if (net ~ 192.168.2.0/24) then { krt_tunnel=""; accept; }`,
				`  if (net ~ 192.168.3.0/24) then { krt_tunnel=""; accept; }`,
			},
		},
		configV6: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			RouterID:            "10.192.0.2",
			ASNumber:            "64512",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			BGPExportFilterForDisabledIPPools: []string{
				`  if (net ~ 2002:102::/64) then { reject; } # BGP export is disabled.`,
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 2002:101::/64) then { accept; }`,
				`  if (net ~ 2002:103::/64) then { accept; }`,
			},
		},
	}
}

func meshIPIPAlways() templateTestCase {
	return templateTestCase{
		name:      "mesh/ipip-always",
		goldenDir: "mesh/ipip-always",
		kvData:    standardIPAMKVData(),
		configV4: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "10.192.0.2",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_10_192_0_3",
					IP:           "10.192.0.3",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
				{
					Name:         "Mesh_10_192_0_4",
					IP:           "10.192.0.4",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { accept; }`,
			},
			KernelFilterForIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { krt_tunnel="tunl0"; accept; }`,
			},
		},
		configV6: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			RouterID:            "10.192.0.2",
			ASNumber:            "64512",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
		},
	}
}

func meshIPIPCrossSubnet() templateTestCase {
	return templateTestCase{
		name:      "mesh/ipip-cross-subnet",
		goldenDir: "mesh/ipip-cross-subnet",
		kvData:    standardIPAMKVData(),
		configV4: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "10.192.0.2",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_10_192_0_3",
					IP:           "10.192.0.3",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
				{
					Name:         "Mesh_10_192_0_6",
					IP:           "10.192.0.6",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { accept; }`,
			},
			KernelFilterForIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { if (defined(bgp_next_hop)&&(bgp_next_hop ~ 10.192.0.0/16)) then krt_tunnel=""; else krt_tunnel="tunl0"; accept; }`,
			},
		},
		configV6: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			RouterID:            "10.192.0.2",
			ASNumber:            "64512",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
		},
	}
}

func meshIPIPOff() templateTestCase {
	return templateTestCase{
		name:      "mesh/ipip-off",
		goldenDir: "mesh/ipip-off",
		kvData:    standardIPAMKVData(),
		configV4: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "10.192.0.2",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_10_192_0_3",
					IP:           "10.192.0.3",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
				{
					Name:         "Mesh_10_192_0_4",
					IP:           "10.192.0.4",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { accept; }`,
			},
			KernelFilterForIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { krt_tunnel=""; accept; }`,
			},
		},
		configV6: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "2001::103",
			NodeIPv6:            "2001::103",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_2001__102",
					IP:           "2001::102",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "2001::103",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
				},
				{
					Name:         "Mesh_2001__104",
					IP:           "2001::104",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "2001::103",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 2002::/64) then { accept; }`,
			},
		},
	}
}

func meshVXLANAlways() templateTestCase {
	return templateTestCase{
		name:      "mesh/vxlan-always",
		goldenDir: "mesh/vxlan-always",
		kvData:    standardIPAMKVData(),
		configV4: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "10.192.0.2",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_10_192_0_3",
					IP:           "10.192.0.3",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
				{
					Name:         "Mesh_10_192_0_4",
					IP:           "10.192.0.4",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "10.192.0.2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { accept; }`,
			},
			KernelFilterForIPPools: []string{
				`  if (net ~ 192.168.0.0/16) then { reject; } # VXLAN routes are handled by Felix.`,
			},
		},
		configV6: &types.BirdBGPConfig{
			NodeName:            "kube-master",
			NodeIP:              "fdf5:10::2",
			NodeIPv6:            "fdf5:10::2",
			ASNumber:            "64512",
			RouterID:            "10.192.0.2",
			DebugMode:           "{ states }",
			DirectInterfaces:    `-"cali*", -"kube-ipvs*", "*"`,
			NormalRoutePriority: 1024,
			Peers: []types.BirdBGPPeer{
				{
					Name:         "Mesh_fdf5_10__3",
					IP:           "fdf5:10::3",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "fdf5:10::2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
				{
					Name:         "Mesh_fdf5_10__4",
					IP:           "fdf5:10::4",
					ASNumber:     "64512",
					Type:         "mesh",
					SourceAddr:   "fdf5:10::2",
					ImportFilter: meshImportFilter,
					ExportFilter: meshExportFilter,
					Passive:      true,
				},
			},
			BGPExportFilterForEnabledIPPools: []string{
				`  if (net ~ dead:beef::/64) then { accept; }`,
			},
			KernelFilterForIPPools: []string{
				`  if (net ~ dead:beef::/64) then { reject; } # VXLAN routes are handled by Felix.`,
			},
		},
	}
}
