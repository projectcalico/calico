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

// Capability is something a lane's cluster has. The same string is the suffix
// of the Requires: label a spec carries and an entry in a cluster fragment's
// provides: list, and the two are compared by equality. Each one has a probe
// in e2e/pkg/capability that confirms a lane declaring it really has it.
type Capability string

const (
	// Operator means tigera-operator installed Calico, so the Installation exists.
	Operator Capability = "Operator"

	// CalicoCNI and CalicoIPAM mean Calico is the CNI plugin and the IPAM plugin,
	// rather than a provider's such as the AWS VPC CNI or Azure CNI.
	CalicoCNI  Capability = "CalicoCNI"
	CalicoIPAM Capability = "CalicoIPAM"

	// AzureIPAM means the Azure CNI allocates pod addresses.
	AzureIPAM Capability = "AzureIPAM"

	// AggregatedAPI means calico-apiserver serves projectcalico.org/v3, which
	// read-path tier RBAC depends on.
	AggregatedAPI Capability = "AggregatedAPI"

	// V3CRDs means kube-apiserver serves projectcalico.org/v3 from CRDs, so
	// disabling the BGP mesh can't cut the Calico API off.
	V3CRDs Capability = "V3CRDs"

	// BGP means BIRD is running. BGPRouting adds that BGP programs the cluster's
	// pod routes, not Felix. BGPMesh adds that the node-to-node mesh is the only
	// path between nodes, so disabling it breaks connectivity.
	BGP        Capability = "BGP"
	BGPRouting Capability = "BGPRouting"
	BGPMesh    Capability = "BGPMesh"

	// NoEncap means every IP pool has IPIP and VXLAN off.
	NoEncap Capability = "NoEncap"

	// BPF and Xtables are the Linux dataplane. Xtables covers both iptables and
	// nftables. BPFDSR adds direct server return for external service traffic.
	BPF     Capability = "BPF"
	BPFDSR  Capability = "BPFDSR"
	Xtables Capability = "Xtables"

	// PolicyTiers and DoNotTrack mean the dataplane implements policy tiers and
	// doNotTrack policy, which VPP doesn't.
	PolicyTiers Capability = "PolicyTiers"
	DoNotTrack  Capability = "DoNotTrack"

	// WireGuard means Felix encrypts pod traffic with WireGuard.
	WireGuard Capability = "WireGuard"

	// HostPorts means the CNI configuration includes the portmap plugin.
	HostPorts Capability = "HostPorts"

	// CalicoMTU means Calico sets the pod interface MTU, which a platform that
	// fixes the MTU itself doesn't allow.
	CalicoMTU Capability = "CalicoMTU"

	// AutoHEPs means kube-controllers creates a host endpoint for every node.
	AutoHEPs Capability = "AutoHEPs"

	// Goldmane means Goldmane and Whisker are installed and ready.
	Goldmane Capability = "Goldmane"

	// AWS and Azure name the cloud the nodes run in. RKE2, OpenShift and RHEL
	// name the Kubernetes distribution and the node OS.
	AWS       Capability = "AWS"
	Azure     Capability = "Azure"
	RKE2      Capability = "RKE2"
	OpenShift Capability = "OpenShift"
	RHEL      Capability = "RHEL"

	// IPv4 and IPv6 mean every node has an address in that family.
	IPv4 Capability = "IPv4"
	IPv6 Capability = "IPv6"

	// KubeVirt means a KubeVirt API is served, real or simulated. RealKubeVirt
	// and MockVirt say which, for specs that only work against one of them.
	KubeVirt     Capability = "KubeVirt"
	RealKubeVirt Capability = "RealKubeVirt"
	MockVirt     Capability = "MockVirt"

	// Istio means Istio is installed alongside Calico.
	Istio Capability = "Istio"

	// ExternalNode means the lane passes the address and SSH key of a host
	// outside the cluster.
	ExternalNode Capability = "ExternalNode"

	// RoutableIPPools means pods can take addresses from an unencapsulated IP
	// pool a spec creates. EKS, AKS and kops route only the addresses their
	// cloud network already knows.
	RoutableIPPools Capability = "RoutableIPPools"

	// NodePortAcrossNodes means a node accepts NodePort traffic from another
	// node, which the AKS and EKS security groups block when the provider's CNI
	// owns the pod network.
	NodePortAcrossNodes Capability = "NodePortAcrossNodes"

	// HostNetworkServices means a host-networked pod can reach a ClusterIP or a
	// NodePort.
	HostNetworkServices Capability = "HostNetworkServices"

	// HostEndpointCrossNode means host endpoint policy drops pod traffic it
	// denies on the way to another node.
	HostEndpointCrossNode Capability = "HostEndpointCrossNode"

	// RapidClientImage means nodes can run the multi-mode rapidclient server
	// image the packet size specs use.
	RapidClientImage Capability = "RapidClientImage"

	// ConnectionLimits means Calico enforces the QoS connection limit
	// annotations.
	ConnectionLimits Capability = "ConnectionLimits"

	// AmbientPolicy means Calico policy is enforced on TCP traffic that Istio
	// ambient mode carries.
	AmbientPolicy Capability = "AmbientPolicy"
)

// Capabilities is every capability a spec may require. The capability check
// probes each of them on every run, so it can report the ones a lane has but
// didn't declare.
var Capabilities = []Capability{
	Operator,
	CalicoCNI,
	CalicoIPAM,
	AzureIPAM,
	AggregatedAPI,
	V3CRDs,
	BGP,
	BGPRouting,
	BGPMesh,
	NoEncap,
	BPF,
	BPFDSR,
	Xtables,
	PolicyTiers,
	DoNotTrack,
	WireGuard,
	HostPorts,
	CalicoMTU,
	AutoHEPs,
	Goldmane,
	AWS,
	Azure,
	RKE2,
	OpenShift,
	RHEL,
	IPv4,
	IPv6,
	KubeVirt,
	RealKubeVirt,
	MockVirt,
	Istio,
	ExternalNode,
	RoutableIPPools,
	NodePortAcrossNodes,
	HostNetworkServices,
	HostEndpointCrossNode,
	RapidClientImage,
	ConnectionLimits,
	AmbientPolicy,
}

// requiresKey is the label key specs declare preconditions under.
const requiresKey = "Requires"

// Requires marks a spec as needing a capability. A lane selects the spec only
// if its cluster fragments provide every capability the spec requires.
func Requires(c Capability) any {
	return framework.WithLabel(requiresKey + ":" + string(c))
}

// RunsAnywhere declares that a spec needs no capability, so it runs on every
// lane whose suites select it. It adds no label; it exists so that having no
// requirements is a visible choice rather than an omission.
func RunsAnywhere() any {
	return []any{}
}

// Covers marks a spec as exercising a feature, for suite includes and for the
// per-feature views on the CI dashboard. The value must be in the coverage
// list, so a typo can't create a feature nobody looks at.
func Covers(feature string) any {
	if !features[feature] {
		framework.Failf("%s is not a supported feature", feature)
	}
	return framework.WithLabel("Covers:" + feature)
}
