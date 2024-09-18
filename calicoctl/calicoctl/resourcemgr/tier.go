// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package resourcemgr

import (
	"context"
	"sort"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewTier(),
		api.NewTierList(),
		false,
		[]string{"tier", "tiers"},
		[]string{"NAME", "ORDER"},
		[]string{"NAME", "ORDER"},
		map[string]string{
			"NAME":  "{{.ObjectMeta.Name}}",
			"ORDER": "{{.Spec.Order}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Tier)
			return client.Tiers().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Tier)
			return client.Tiers().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Tier)
			return client.Tiers().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Tier)
			return client.Tiers().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.Tier)
			tierList, err := client.Tiers().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
			if err != nil {
				return tierList, err
			}

			// Sort the output by order
			sort.SliceStable(tierList.Items, func(tier1, tier2 int) bool {
				if tierList.Items[tier1].Spec.Order == nil {
					return false
				}

				if tierList.Items[tier2].Spec.Order == nil {
					return true
				}

				return *tierList.Items[tier1].Spec.Order < *tierList.Items[tier2].Spec.Order
			})

			return tierList, nil
		},
	)
}
