// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	projectcalicov3 "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	gentype "k8s.io/client-go/gentype"
)

// fakeStagedKubernetesNetworkPolicies implements StagedKubernetesNetworkPolicyInterface
type fakeStagedKubernetesNetworkPolicies struct {
	*gentype.FakeClientWithList[*v3.StagedKubernetesNetworkPolicy, *v3.StagedKubernetesNetworkPolicyList]
	Fake *FakeProjectcalicoV3
}

func newFakeStagedKubernetesNetworkPolicies(fake *FakeProjectcalicoV3, namespace string) projectcalicov3.StagedKubernetesNetworkPolicyInterface {
	return &fakeStagedKubernetesNetworkPolicies{
		gentype.NewFakeClientWithList[*v3.StagedKubernetesNetworkPolicy, *v3.StagedKubernetesNetworkPolicyList](
			fake.Fake,
			namespace,
			v3.SchemeGroupVersion.WithResource("stagedkubernetesnetworkpolicies"),
			v3.SchemeGroupVersion.WithKind("StagedKubernetesNetworkPolicy"),
			func() *v3.StagedKubernetesNetworkPolicy { return &v3.StagedKubernetesNetworkPolicy{} },
			func() *v3.StagedKubernetesNetworkPolicyList { return &v3.StagedKubernetesNetworkPolicyList{} },
			func(dst, src *v3.StagedKubernetesNetworkPolicyList) { dst.ListMeta = src.ListMeta },
			func(list *v3.StagedKubernetesNetworkPolicyList) []*v3.StagedKubernetesNetworkPolicy {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v3.StagedKubernetesNetworkPolicyList, items []*v3.StagedKubernetesNetworkPolicy) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
