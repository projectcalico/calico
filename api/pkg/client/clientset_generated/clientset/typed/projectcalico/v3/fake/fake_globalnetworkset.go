// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	projectcalicov3 "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	gentype "k8s.io/client-go/gentype"
)

// fakeGlobalNetworkSets implements GlobalNetworkSetInterface
type fakeGlobalNetworkSets struct {
	*gentype.FakeClientWithList[*v3.GlobalNetworkSet, *v3.GlobalNetworkSetList]
	Fake *FakeProjectcalicoV3
}

func newFakeGlobalNetworkSets(fake *FakeProjectcalicoV3) projectcalicov3.GlobalNetworkSetInterface {
	return &fakeGlobalNetworkSets{
		gentype.NewFakeClientWithList[*v3.GlobalNetworkSet, *v3.GlobalNetworkSetList](
			fake.Fake,
			"",
			v3.SchemeGroupVersion.WithResource("globalnetworksets"),
			v3.SchemeGroupVersion.WithKind("GlobalNetworkSet"),
			func() *v3.GlobalNetworkSet { return &v3.GlobalNetworkSet{} },
			func() *v3.GlobalNetworkSetList { return &v3.GlobalNetworkSetList{} },
			func(dst, src *v3.GlobalNetworkSetList) { dst.ListMeta = src.ListMeta },
			func(list *v3.GlobalNetworkSetList) []*v3.GlobalNetworkSet { return gentype.ToPointerSlice(list.Items) },
			func(list *v3.GlobalNetworkSetList, items []*v3.GlobalNetworkSet) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
