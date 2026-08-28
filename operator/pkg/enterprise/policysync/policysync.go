// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package policysync

import (
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
)

// ApplicationLayerRequires reports whether any enabled ApplicationLayer feature needs
// policySyncPathPrefix set. A nil CR returns false.
func ApplicationLayerRequires(al *operatorv1.ApplicationLayer) bool {
	if al == nil {
		return false
	}
	spec := &al.Spec
	if spec.LogCollection != nil && spec.LogCollection.CollectLogs != nil &&
		*spec.LogCollection.CollectLogs == operatorv1.L7LogCollectionEnabled {
		return true
	}
	if spec.WebApplicationFirewall != nil &&
		*spec.WebApplicationFirewall == operatorv1.WAFEnabled {
		return true
	}
	if spec.ApplicationLayerPolicy != nil &&
		*spec.ApplicationLayerPolicy == operatorv1.ApplicationLayerPolicyEnabled {
		return true
	}
	if spec.SidecarInjection != nil &&
		*spec.SidecarInjection == operatorv1.SidecarEnabled {
		return true
	}
	return false
}
