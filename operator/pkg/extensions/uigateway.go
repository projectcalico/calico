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

package extensions

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// UIGatewayExtension is the variant's hook into the ingress gateway a UI
// component (Manager, Whisker) exposes itself through.
type UIGatewayExtension interface {
	// ProxyObjects returns the variant's objects rendered beside the named
	// component's gateway proxy in the backend namespace, or nil when the
	// variant adds none.
	ProxyObjects(resourcePrefix, namespace string) []client.Object
}

// noopUIGateway runs the core operator's behavior unchanged.
type noopUIGateway struct{}

func (noopUIGateway) ProxyObjects(string, string) []client.Object { return nil }
