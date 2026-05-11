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

package validation_test

import (
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// expectApplySucceeds asserts that a server-side apply of obj succeeds. This is
// the same code path used by FluxCD, ArgoCD, and `kubectl apply --server-side`,
// and exercises the structural-merge-diff schema built from the CRD's listType,
// listMapKey, and mapType annotations. CRDs that misuse those annotations
// (e.g. listType=set on a list of objects) fail to build a typed schema and
// produce errors like "associative list without keys has an element that's a
// map type", regardless of the spec content.
func expectApplySucceeds(t *testing.T, obj client.Object) {
	t.Helper()
	ctx := context.Background()
	err := testClient.Patch(ctx, obj, client.Apply,
		client.FieldOwner("validation-test"),
		client.ForceOwnership)
	if err != nil {
		t.Fatalf("expected server-side apply to succeed but got: %v", err)
	}
	t.Cleanup(func() {
		_ = testClient.Delete(context.Background(), obj)
	})
}

// TestBGPConfiguration_ServerSideApply locks in the fix for
// https://github.com/projectcalico/calico/issues/12700. Each of the object-list
// fields below was tagged +listType=set in v3.32.0, which is invalid for lists
// of objects and breaks any server-side-apply client. Apply must succeed for
// all of them.
func TestBGPConfiguration_ServerSideApply(t *testing.T) {
	tests := []struct {
		name string
		spec v3.BGPConfigurationSpec
	}{
		{
			name: "serviceLoadBalancerIPs populated",
			spec: v3.BGPConfigurationSpec{
				ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{
					{CIDR: "10.0.0.0/24"},
					{CIDR: "10.1.0.0/24"},
				},
			},
		},
		{
			name: "serviceExternalIPs populated",
			spec: v3.BGPConfigurationSpec{
				ServiceExternalIPs: []v3.ServiceExternalIPBlock{
					{CIDR: "192.168.0.0/24"},
				},
			},
		},
		{
			name: "serviceClusterIPs populated",
			spec: v3.BGPConfigurationSpec{
				ServiceClusterIPs: []v3.ServiceClusterIPBlock{
					{CIDR: "172.16.0.0/16"},
				},
			},
		},
		{
			name: "communities populated",
			spec: v3.BGPConfigurationSpec{
				Communities: []v3.Community{
					{Name: "my-community", Value: "65001:100"},
				},
				PrefixAdvertisements: []v3.PrefixAdvertisement{
					{CIDR: "10.0.0.0/24", Communities: []string{"my-community"}},
				},
			},
		},
		{
			name: "prefixAdvertisements populated",
			spec: v3.BGPConfigurationSpec{
				PrefixAdvertisements: []v3.PrefixAdvertisement{
					{CIDR: "10.0.0.0/24", Communities: []string{"65001:100"}},
				},
			},
		},
		{
			name: "all object lists populated together",
			spec: v3.BGPConfigurationSpec{
				ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "10.0.0.0/24"}},
				ServiceExternalIPs:     []v3.ServiceExternalIPBlock{{CIDR: "192.168.0.0/24"}},
				ServiceClusterIPs:      []v3.ServiceClusterIPBlock{{CIDR: "172.16.0.0/16"}},
				Communities:            []v3.Community{{Name: "my-community", Value: "65001:100"}},
				PrefixAdvertisements: []v3.PrefixAdvertisement{
					{CIDR: "10.0.0.0/24", Communities: []string{"my-community"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &v3.BGPConfiguration{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v3.GroupVersionCurrent,
					Kind:       v3.KindBGPConfiguration,
				},
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpconfig-ssa")},
				Spec:       tt.spec,
			}
			expectApplySucceeds(t, obj)
		})
	}
}

// populatedRule returns a Rule with inner list fields populated, so that smd
// walks into Source/Destination Nets and any other rule-internal lists.
func populatedRule() v3.Rule {
	return v3.Rule{
		Action:   v3.Allow,
		Protocol: ptr.To(numorstring.ProtocolFromString("TCP")),
		Source: v3.EntityRule{
			Nets:    []string{"10.0.0.0/24"},
			NotNets: []string{"10.0.1.0/24"},
			Ports:   []numorstring.Port{numorstring.SinglePort(80)},
		},
		Destination: v3.EntityRule{
			Nets:    []string{"10.1.0.0/24"},
			NotNets: []string{"10.1.1.0/24"},
			Ports:   []numorstring.Port{numorstring.SinglePort(443)},
		},
	}
}

func TestBGPFilter_ServerSideApply(t *testing.T) {
	obj := &v3.BGPFilter{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindBGPFilter,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter-ssa")},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{
				{CIDR: "10.0.0.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
			},
			ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: "10.1.0.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			},
			ExportV6: []v3.BGPFilterRuleV6{
				{CIDR: "fd00::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
			},
			ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: "fd01::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestBGPPeer_ServerSideApply(t *testing.T) {
	obj := &v3.BGPPeer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindBGPPeer,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer-ssa")},
		Spec: v3.BGPPeerSpec{
			PeerIP:   "10.0.0.1",
			ASNumber: numorstring.ASNumber(64512),
			Filters:  []string{"my-filter"},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestBlockAffinity_ServerSideApply(t *testing.T) {
	obj := &v3.BlockAffinity{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindBlockAffinity,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("blockaffinity-ssa")},
		Spec: v3.BlockAffinitySpec{
			State: v3.StateConfirmed,
			Node:  "mynode",
			CIDR:  "10.0.0.0/26",
		},
	}
	expectApplySucceeds(t, obj)
}

func TestCalicoNodeStatus_ServerSideApply(t *testing.T) {
	obj := &v3.CalicoNodeStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindCalicoNodeStatus,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("nodestatus-ssa")},
		Spec: v3.CalicoNodeStatusSpec{
			Node: "mynode",
			Classes: []v3.NodeStatusClassType{
				v3.NodeStatusClassTypeAgent,
				v3.NodeStatusClassTypeBGP,
				v3.NodeStatusClassTypeRoutes,
			},
			UpdatePeriodSeconds: ptr.To(uint32(60)),
		},
	}
	expectApplySucceeds(t, obj)
}

func TestClusterInformation_ServerSideApply(t *testing.T) {
	// ClusterInformation has no list fields on its spec, but we still cover the
	// SSA path to ensure the typed schema builds.
	obj := &v3.ClusterInformation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindClusterInformation,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("clusterinfo-ssa")},
		Spec: v3.ClusterInformationSpec{
			ClusterGUID:    "abc-123",
			ClusterType:    "k8s,bgp",
			CalicoVersion:  "v3.30.0",
			DatastoreReady: ptr.To(true),
			Variant:        "Calico",
		},
	}
	expectApplySucceeds(t, obj)
}

func TestFelixConfiguration_ServerSideApply(t *testing.T) {
	obj := &v3.FelixConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindFelixConfiguration,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig-ssa")},
		Spec: v3.FelixConfigurationSpec{
			RouteTableRanges: &v3.RouteTableRanges{{Min: 1, Max: 250}},
			HealthTimeoutOverrides: []v3.HealthTimeoutOverride{
				{Name: "InternalDataplaneMainLoop", Timeout: metav1.Duration{Duration: 0}},
			},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestGlobalNetworkPolicy_ServerSideApply(t *testing.T) {
	obj := &v3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp-ssa")},
		Spec: v3.GlobalNetworkPolicySpec{
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{populatedRule()},
			Egress:   []v3.Rule{populatedRule()},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestGlobalNetworkSet_ServerSideApply(t *testing.T) {
	obj := &v3.GlobalNetworkSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindGlobalNetworkSet,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gns-ssa")},
		Spec: v3.GlobalNetworkSetSpec{
			Nets: []string{"10.0.0.0/24", "10.1.0.0/24"},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestHostEndpoint_ServerSideApply(t *testing.T) {
	obj := &v3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("hep-ssa")},
		Spec: v3.HostEndpointSpec{
			Node:          "mynode",
			InterfaceName: "eth0",
			ExpectedIPs:   []string{"10.0.0.1", "fd00::1"},
			Profiles:      []string{"profile-a"},
			Ports: []v3.EndpointPort{
				{Name: "http", Protocol: numorstring.ProtocolFromString("TCP"), Port: 80},
			},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestIPAMBlock_ServerSideApply(t *testing.T) {
	// IPAMBlock and IPAMHandle have no Kind constants in the v3 package, so
	// we hard-code the strings (matching the CRD's spec.names.kind).
	allocations := []*int{ptr.To(0)}
	obj := &v3.IPAMBlock{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       "IPAMBlock",
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ipamblock-ssa")},
		Spec: v3.IPAMBlockSpec{
			CIDR:        "10.0.0.0/26",
			Affinity:    ptr.To("host:mynode"),
			Allocations: allocations,
			Unallocated: []int{1, 2, 3},
			Attributes: []v3.AllocationAttribute{
				{HandleID: ptr.To("handle-1")},
			},
			SequenceNumberForAllocation: map[string]uint64{"0": 1},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestIPAMConfiguration_ServerSideApply(t *testing.T) {
	obj := &v3.IPAMConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindIPAMConfiguration,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ipamconfig-ssa")},
		Spec: v3.IPAMConfigurationSpec{
			StrictAffinity:     true,
			MaxBlocksPerHost:   8,
			AutoAllocateBlocks: true,
		},
	}
	expectApplySucceeds(t, obj)
}

func TestIPAMHandle_ServerSideApply(t *testing.T) {
	obj := &v3.IPAMHandle{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       "IPAMHandle",
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ipamhandle-ssa")},
		Spec: v3.IPAMHandleSpec{
			HandleID: "handle-id-1",
			Block:    map[string]int{"10.0.0.0/26": 1},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestIPPool_ServerSideApply(t *testing.T) {
	obj := &v3.IPPool{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindIPPool,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool-ssa")},
		Spec: v3.IPPoolSpec{
			CIDR:           nextPoolCIDR(),
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel},
			AssignmentMode: ptr.To(v3.Automatic),
		},
	}
	expectApplySucceeds(t, obj)
}

func TestIPReservation_ServerSideApply(t *testing.T) {
	obj := &v3.IPReservation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindIPReservation,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ipres-ssa")},
		Spec: v3.IPReservationSpec{
			ReservedCIDRs: []string{"10.0.0.0/24", "10.1.0.0/24"},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestKubeControllersConfiguration_ServerSideApply(t *testing.T) {
	obj := &v3.KubeControllersConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindKubeControllersConfiguration,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("kcc-ssa")},
		Spec: v3.KubeControllersConfigurationSpec{
			Controllers: v3.ControllersConfig{
				Node: &v3.NodeControllerConfig{
					HostEndpoint: &v3.AutoHostEndpointConfig{
						AutoCreate: "Enabled",
						Templates: []v3.Template{
							{
								GenerateName:   "tmpl",
								InterfaceCIDRs: []string{"10.0.0.0/24"},
							},
						},
					},
				},
			},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestNetworkPolicy_ServerSideApply(t *testing.T) {
	obj := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np-ssa"), Namespace: "default"},
		Spec: v3.NetworkPolicySpec{
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{populatedRule()},
			Egress:   []v3.Rule{populatedRule()},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestNetworkSet_ServerSideApply(t *testing.T) {
	obj := &v3.NetworkSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindNetworkSet,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ns-ssa"), Namespace: "default"},
		Spec: v3.NetworkSetSpec{
			Nets: []string{"10.0.0.0/24", "10.1.0.0/24"},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestStagedGlobalNetworkPolicy_ServerSideApply(t *testing.T) {
	obj := &v3.StagedGlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindStagedGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp-ssa")},
		Spec: v3.StagedGlobalNetworkPolicySpec{
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{populatedRule()},
			Egress:   []v3.Rule{populatedRule()},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestStagedKubernetesNetworkPolicy_ServerSideApply(t *testing.T) {
	obj := &v3.StagedKubernetesNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindStagedKubernetesNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sknp-ssa"), Namespace: "default"},
		Spec: v3.StagedKubernetesNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: ptr.To(corev1.ProtocolTCP), Port: nil},
					},
					From: []networkingv1.NetworkPolicyPeer{
						{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/24", Except: []string{"10.0.0.1/32"}}},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: ptr.To(corev1.ProtocolTCP)},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{IPBlock: &networkingv1.IPBlock{CIDR: "10.1.0.0/24"}},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestStagedNetworkPolicy_ServerSideApply(t *testing.T) {
	obj := &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindStagedNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("snp-ssa"), Namespace: "default"},
		Spec: v3.StagedNetworkPolicySpec{
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{populatedRule()},
			Egress:   []v3.Rule{populatedRule()},
		},
	}
	expectApplySucceeds(t, obj)
}

func TestTier_ServerSideApply(t *testing.T) {
	obj := &v3.Tier{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v3.GroupVersionCurrent,
			Kind:       v3.KindTier,
		},
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("tier-ssa")},
		Spec: v3.TierSpec{
			DefaultAction: ptr.To(v3.Deny),
		},
	}
	expectApplySucceeds(t, obj)
}
