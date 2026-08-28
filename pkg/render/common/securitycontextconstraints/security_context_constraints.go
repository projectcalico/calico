// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package securitycontextconstraints

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	ocsv1 "github.com/openshift/api/security/v1"
)

// Default OpenShift security context constraints (SCCs) defined in
// https://docs.openshift.com/container-platform/4.14/authentication/managing-security-context-constraints.html#default-sccs_configuring-internal-oauth
const (
	HostAccess    = "hostaccess"
	HostNetworkV2 = "hostnetwork-v2"
	NonRootV2     = "nonroot-v2"
	Privileged    = "privileged"
)

// NewNonRootSecurityContextConstraints is translated from the default security context constraints nonroot-v2.
func NewNonRootSecurityContextConstraints(name string, users []string) *ocsv1.SecurityContextConstraints {
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:   metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},

		AllowHostDirVolumePlugin: false,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             false,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: ptr.To(false),
		AllowPrivilegedContainer: false,
		FSGroup:                  ocsv1.FSGroupStrategyOptions{Type: ocsv1.FSGroupStrategyRunAsAny},
		ReadOnlyRootFilesystem:   false,
		RequiredDropCapabilities: []corev1.Capability{"ALL"},
		RunAsUser:                ocsv1.RunAsUserStrategyOptions{Type: ocsv1.RunAsUserStrategyMustRunAsNonRoot},
		SELinuxContext:           ocsv1.SELinuxContextStrategyOptions{Type: ocsv1.SELinuxStrategyMustRunAs},
		SeccompProfiles:          []string{"runtime/default"},
		SupplementalGroups:       ocsv1.SupplementalGroupsStrategyOptions{Type: ocsv1.SupplementalGroupsStrategyRunAsAny},
		Users:                    users,
		Volumes: []ocsv1.FSType{
			ocsv1.FSProjected,
			ocsv1.FSTypeCSI,
			ocsv1.FSTypeConfigMap,
			ocsv1.FSTypeDownwardAPI,
			ocsv1.FSTypeEmptyDir,
			ocsv1.FSTypeEphemeral,
			ocsv1.FSTypePersistentVolumeClaim,
			ocsv1.FSTypeSecret,
		},
	}
}
