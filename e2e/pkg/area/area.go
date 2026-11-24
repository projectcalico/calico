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

// Package area names the feature areas e2e specs exercise, which suites select
// on and the CI dashboard groups results by.
package area

// Area is a feature area a spec exercises. The same string is the suffix of
// the Covers: label a spec carries. If you are unsure which area a spec
// belongs to, ask.
type Area string

const (
	NetworkPolicy   Area = "NetworkPolicy"
	TieredPolicy    Area = "Tiered-Policy"
	IPPool          Area = "IPPool"
	IPAM            Area = "IPAM"
	AutoHEPs        Area = "AutoHEPs"
	HostProtection  Area = "Host-Protection"
	HostPorts       Area = "HostPorts"
	OwnerReferences Area = "OwnerReferences"
	MTU             Area = "MTU"
	Maglev          Area = "Maglev"
	BGPPeer         Area = "BGPPeer"
	IPIP            Area = "IPIP"
	TieredRBAC      Area = "Tiered-RBAC"
	Pods            Area = "Pods"
	QoS             Area = "QoS"
	Datapath        Area = "Datapath"
	IngressGateway  Area = "IngressGateway"
	Istio           Area = "Istio"
	KubeVirt        Area = "KubeVirt"
	Wireguard       Area = "Wireguard"
	FlowLogs        Area = "Flow-Logs"
	Windows         Area = "Windows"
)

// All is every area a spec may cover. describe.Covers rejects anything else,
// and the repo config tests check that suite includes only name areas in it.
var All = []Area{
	NetworkPolicy,
	TieredPolicy,
	IPPool,
	IPAM,
	AutoHEPs,
	HostProtection,
	HostPorts,
	OwnerReferences,
	MTU,
	Maglev,
	BGPPeer,
	IPIP,
	TieredRBAC,
	Pods,
	QoS,
	Datapath,
	IngressGateway,
	Istio,
	KubeVirt,
	Wireguard,
	FlowLogs,
	Windows,
}

// IsKnown reports whether a is in All.
func IsKnown(a Area) bool {
	for _, known := range All {
		if known == a {
			return true
		}
	}
	return false
}
