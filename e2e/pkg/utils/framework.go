// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
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
	"k8s.io/kubernetes/test/e2e/framework"
	admission "k8s.io/pod-security-admission/api"
)

// The default pod security admission level for a test namespace is restricted in most managed public cloud.
// The PodSecurity admission controller sets annotation "pod-security.kubernetes.io/enforce: restricted" on
// a test namespace. This will block e2e to create any pod without a restricted security context.
// We need to set admission level to priviledged for any test namespace to work around this issue.
func NewDefaultFramework(name string) *framework.Framework {
	f := framework.NewDefaultFramework(name)
	f.NamespacePodSecurityEnforceLevel = admission.LevelPrivileged
	return f
}
