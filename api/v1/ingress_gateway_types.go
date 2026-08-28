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

package v1

// IngressGatewaySpec configures Calico Ingress Gateway access for a UI component.
// When set, the operator renders Gateway API resources (Gateway, HTTPRoute,
// Backend, ReferenceGrant, TLS Secret) to expose the component via CIG.
type IngressGatewaySpec struct {
	// Hostname for the Gateway listener. Must match the Authentication CR's
	// managerDomain when OIDC is configured (Manager only).
	// +kubebuilder:validation:MinLength=1
	Hostname string `json:"hostname"`

	// GatewayNamespace is the namespace where the Gateway and Envoy Proxy pods
	// run. Defaults to "calico-system".
	// +optional
	GatewayNamespace *string `json:"gatewayNamespace,omitempty"`

	// GatewayClassName selects the GatewayClass for the Gateway resource.
	// If not set and the GatewayAPI CR has exactly one class, that class is
	// used. If not set and multiple classes exist, the controller sets a
	// warning requiring the user to specify one.
	// +optional
	GatewayClassName *string `json:"gatewayClassName,omitempty"`
}

// NamespaceOrDefault returns the configured gateway namespace or "calico-system".
func (g *IngressGatewaySpec) NamespaceOrDefault() string {
	if g.GatewayNamespace != nil && *g.GatewayNamespace != "" {
		return *g.GatewayNamespace
	}
	return "calico-system"
}
