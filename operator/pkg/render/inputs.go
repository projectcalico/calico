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

package render

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Inputs is the raw cluster state a controller gathered, carried into render
// modifiers. Only modifiers read it; core operator code never does.
//
// Per-component config is not carried here. A modifier is handed the same typed
// config the core operator rendered the component from.
type Inputs struct {
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	ClusterDomain      string

	// TrustedBundle is the shared CA bundle for the calico-system namespace.
	TrustedBundle certificatemanagement.TrustedBundle

	// Extension is opaque data the controller extension produced, usually an artifact
	// that can only be created controller-side because it has cluster side effects
	// (a keypair, say). Where a controller needs to read it back, the payload is a
	// render type so it does not depend on the extension. Nil when none is active.
	Extension any
}

// ExtractExtensionData returns the Extension slot asserted to T, or the zero value
// of T when it is empty or holds a different type.
func ExtractExtensionData[T any](ri Inputs) T {
	data, _ := ri.Extension.(T)
	return data
}
