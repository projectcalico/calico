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

package utils

import (
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
)

// DefaultPolicySyncPrefix is the operator-managed value for
// FelixConfiguration.policySyncPathPrefix. The applicationlayer and istio
// controllers both write this value when their respective features need a
// running policy-sync gRPC server on the host (Dikastes sidecar, Istio
// ambient waypoint l7-collector, EGW).
const DefaultPolicySyncPrefix = "/var/run/nodeagent"

// IstioRequiresPolicySync reports whether an Istio CR is active in a way
// that requires policySyncPathPrefix to be set. The L7 ambient waypoint
// resources (l7-collector sidecar + EnvoyFilter) are rendered when the
// installation variant is Enterprise and waypoint logging is enabled; this
// predicate mirrors that gate (via the shared WaypointLoggingEnabled helper)
// so the FelixConfiguration field tracks the renderer — including when
// waypoint logging is explicitly Disabled.
func IstioRequiresPolicySync(istio *operatorv1.Istio, variant operatorv1.ProductVariant) bool {
	return istio != nil && variant.IsEnterprise() && istio.WaypointLoggingEnabled()
}

// DesiredPolicySyncPathPrefix returns the value FelixConfiguration's
// policySyncPathPrefix should hold given the currently set value and
// whether either the applicationlayer or istio controllers need it.
//
//   - Any non-empty existing value is preserved. This covers both a customer
//     override and the operator-managed default claimed by another controller
//     that shares this field (egressgateway, Gateway API) and never clears it.
//     Those controllers only ever set the default or leave it; clearing it here
//     would break them, so the applicationlayer and istio controllers likewise
//     never clear a value they may not own.
//   - When the field is empty and either controller needs it, the
//     operator-managed default is returned.
//   - Otherwise the field stays empty.
//
// Both the applicationlayer and istio controllers call this from their set and
// cleanup paths to keep coordination explicit and symmetric.
func DesiredPolicySyncPathPrefix(existing string, alNeeds, istioNeeds bool) string {
	if existing != "" {
		return existing
	}
	if alNeeds || istioNeeds {
		return DefaultPolicySyncPrefix
	}
	return ""
}
