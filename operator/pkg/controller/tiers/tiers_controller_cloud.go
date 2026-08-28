// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package tiers

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// cloudPatchTier removes the app.kubernetes.io/instance label from the calico-system tier to fix
// Calico Cloud CD sync (the label is applied out-of-band by Argo CD and confuses its diffing).
// Only invoked for cloud installs.
// TODO(cloud): consider folding this into the tier render instead of a post-create patch.
func (r *ReconcileTiers) cloudPatchTier(ctx context.Context) error {
	tier := &v3.Tier{}
	err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, tier)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if tier.Labels["app.kubernetes.io/instance"] != "" {
		tierPatchFrom := client.MergeFrom(tier.DeepCopy())
		delete(tier.Labels, "app.kubernetes.io/instance")

		if err = r.client.Patch(ctx, tier, tierPatchFrom); err != nil {
			return err
		}
	}
	return nil
}
