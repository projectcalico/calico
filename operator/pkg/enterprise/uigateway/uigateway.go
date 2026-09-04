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

// Package uigateway layers the Calico Enterprise pieces onto a UI component's
// ingress gateway. The common gateway code carries no variant knowledge; an
// Enterprise controller passes what this package builds, and an OSS controller
// passes nothing.
package uigateway

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	rgatewayapi "github.com/projectcalico/calico/operator/pkg/render/gatewayapi"
)

// ProxyObjects returns the Enterprise-only objects that run beside a UI
// gateway's Envoy proxy in the backend namespace: the WAF HTTP filter's
// ServiceAccount and the RoleBinding giving it Gateway API reads.
func ProxyObjects(namespace string) []client.Object {
	return []client.Object{
		rgatewayapi.GatewayNamespaceServiceAccount(namespace),
		rgatewayapi.GatewayNamespaceRoleBinding(namespace),
	}
}
