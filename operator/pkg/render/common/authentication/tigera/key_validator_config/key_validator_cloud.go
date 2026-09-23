// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package tigerakvc

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// CloudAuthenticationConfig holds Calico Cloud specific authentication settings. It is only
// populated for cloud installs (via WithTenantClaim); for regular Calico/Calico Enterprise
// installs requireTenantClaim is false and addCloudEnvs is a no-op, so no cloud env vars are
// emitted and enterprise behavior is unchanged.
type CloudAuthenticationConfig struct {
	requireTenantClaim bool
	tenantID           string
}

// WithTenantClaim configures the KeyValidatorConfig to require and validate a Calico Cloud tenant
// claim. It must only be supplied for cloud installs.
func WithTenantClaim(tenantID string) Option {
	return func(config *KeyValidatorConfig) {
		config.cloud.requireTenantClaim = true
		config.cloud.tenantID = tenantID
	}
}

func (kvc *KeyValidatorConfig) addCloudEnvs(prefix string, envs []corev1.EnvVar) []corev1.EnvVar {
	if !kvc.cloud.requireTenantClaim {
		return envs
	}
	return append(envs,
		corev1.EnvVar{Name: fmt.Sprintf("%sCALICO_CLOUD_REQUIRE_TENANT_CLAIM", prefix), Value: "true"},
		corev1.EnvVar{Name: fmt.Sprintf("%sCALICO_CLOUD_TENANT_CLAIM", prefix), Value: kvc.cloud.tenantID},
	)
}
