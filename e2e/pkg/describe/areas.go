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

package describe

import (
	"k8s.io/kubernetes/test/e2e/framework"
)

// Area is a feature area a spec exercises. The same string is the suffix of
// the Covers: label, which suite includes select on and the CI dashboard
// groups results by. If you are unsure which area a spec belongs to, ask.
type Area string

const (
	AreaNetworkPolicy   Area = "NetworkPolicy"
	AreaTieredPolicy    Area = "Tiered-Policy"
	AreaIPPool          Area = "IPPool"
	AreaIPAM            Area = "IPAM"
	AreaAutoHEPs        Area = "AutoHEPs"
	AreaHostProtection  Area = "Host-Protection"
	AreaHostPorts       Area = "HostPorts"
	AreaOwnerReferences Area = "OwnerReferences"
	AreaMTU             Area = "MTU"
	AreaMaglev          Area = "Maglev"
	AreaBGPPeer         Area = "BGPPeer"
	AreaIPIP            Area = "IPIP"
	AreaTieredRBAC      Area = "Tiered-RBAC"
	AreaPods            Area = "Pods"
	AreaQoS             Area = "QoS"
	AreaDatapath        Area = "Datapath"
	AreaIngressGateway  Area = "IngressGateway"
	AreaIstio           Area = "Istio"
	AreaKubeVirt        Area = "KubeVirt"
	AreaWireguard       Area = "Wireguard"
	AreaFlowLogs        Area = "Flow-Logs"
	AreaWindows         Area = "Windows"
)

// Areas is every area a spec may cover. Covers rejects anything else, and the
// repo config tests check that suite includes only name areas in this list.
var Areas = []Area{
	AreaNetworkPolicy,
	AreaTieredPolicy,
	AreaIPPool,
	AreaIPAM,
	AreaAutoHEPs,
	AreaHostProtection,
	AreaHostPorts,
	AreaOwnerReferences,
	AreaMTU,
	AreaMaglev,
	AreaBGPPeer,
	AreaIPIP,
	AreaTieredRBAC,
	AreaPods,
	AreaQoS,
	AreaDatapath,
	AreaIngressGateway,
	AreaIstio,
	AreaKubeVirt,
	AreaWireguard,
	AreaFlowLogs,
	AreaWindows,
}

// coversKey is the label key specs declare their feature area under.
const coversKey = "Covers"

// Covers marks a spec as exercising a feature area, for suite includes and for
// the per-area views on the CI dashboard. A value converted from a string
// outside Areas fails the spec tree, so a typo can't create an area nobody
// looks at.
func Covers(area Area) any {
	if !IsArea(area) {
		framework.Failf("%s is not a supported area", area)
	}
	return framework.WithLabel(coversKey + ":" + string(area))
}

// IsArea reports whether area is in Areas.
func IsArea(area Area) bool {
	for _, a := range Areas {
		if a == area {
			return true
		}
	}
	return false
}
