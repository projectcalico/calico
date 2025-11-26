// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package resources

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func DefaultTierFields(res *apiv3.Tier) {
	// nil order was allowed before, and it was used for the default tier.
	// For the implementation of ClusterNetworkPolicy, we need to add a tier
	// after the default one. As such, the default tier order is changed to 1,000,000 from nil.
	// To keep the behavior in sync with user defined tiers with nil order, nil order is
	// treated similar to the value of 1,000,000.
	if res.Spec.Order == nil {
		order := apiv3.DefaultTierOrder
		res.Spec.Order = &order
	}
	if res.Spec.DefaultAction == nil {
		actionDeny := apiv3.Deny
		res.Spec.DefaultAction = &actionDeny
	}
}
