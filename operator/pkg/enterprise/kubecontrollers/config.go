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

package kubecontrollers

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	rkc "github.com/tigera/operator/pkg/render/kubecontrollers"
)

// Configuration is the es-calico-kube-controllers input. The embedded generic
// configuration is what the base renderer reads; the fields here are the ones only
// this assembler consumes.
type Configuration struct {
	*rkc.KubeControllersConfiguration

	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection

	// Tenant configures both single and multi-tenant modes. Nil means zero-tenant.
	Tenant *operatorv1.Tenant

	// TenantID is the Calico Cloud tenant, read only when Tenant is nil.
	TenantID string

	// Cloud reports whether this is a Calico Cloud install.
	Cloud bool
}
