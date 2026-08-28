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

// Package rbacmanagement reads the admin-owned gate that switches the RBAC
// management UI on for a cluster.
package rbacmanagement

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

const (
	// ConfigMapName is the admin-owned switch for the RBAC management UI, read by the
	// operator, ui-apis and rbacsync. Keep in sync with ui-apis rbacmanagement/gate.
	ConfigMapName = "rbac-ui-config"
	ConfigMapKey  = "rbac-ui-enabled"

	// LDAPConfigSecretName is the RBAC-UI LDAP directory-sync config Secret
	// (calico-system) the rbacsync process reads to perform the sync.
	// Keep in sync with ui-apis rbacmanagement/idp LDAPConfigSecretName.
	LDAPConfigSecretName = "tigera-idp-ldap-config"

	// GroupsConfigMapName is the ConfigMap (calico-system) holding the IdP group
	// mappings. The manager writes it through ui-apis; rbacsync reads it.
	GroupsConfigMapName = "tigera-idp-groups"
)

// Enabled reports whether the RBAC management UI is switched on for this cluster.
// A missing ConfigMap, missing key or unparsable value reads as disabled.
func Enabled(cm *corev1.ConfigMap) bool {
	if cm == nil {
		return false
	}
	enabled, err := strconv.ParseBool(cm.Data[ConfigMapKey])
	return err == nil && enabled
}
