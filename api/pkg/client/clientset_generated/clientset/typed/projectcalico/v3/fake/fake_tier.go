// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	projectcalicov3 "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	gentype "k8s.io/client-go/gentype"
)

// fakeTiers implements TierInterface
type fakeTiers struct {
	*gentype.FakeClientWithList[*v3.Tier, *v3.TierList]
	Fake *FakeProjectcalicoV3
}

func newFakeTiers(fake *FakeProjectcalicoV3) projectcalicov3.TierInterface {
	return &fakeTiers{
		gentype.NewFakeClientWithList[*v3.Tier, *v3.TierList](
			fake.Fake,
			"",
			v3.SchemeGroupVersion.WithResource("tiers"),
			v3.SchemeGroupVersion.WithKind("Tier"),
			func() *v3.Tier { return &v3.Tier{} },
			func() *v3.TierList { return &v3.TierList{} },
			func(dst, src *v3.TierList) { dst.ListMeta = src.ListMeta },
			func(list *v3.TierList) []*v3.Tier { return gentype.ToPointerSlice(list.Items) },
			func(list *v3.TierList, items []*v3.Tier) { list.Items = gentype.FromPointerSlice(items) },
		),
		fake,
	}
}
