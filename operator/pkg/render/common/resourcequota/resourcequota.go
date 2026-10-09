// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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
//

package resourcequota

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CalicoCriticalResourceQuotaName = "calico-critical-pods"
	TigeraCriticalResourceQuotaName = "tigera-critical-pods"
)

// ResourceQuotaForPriorityClassScope creates a ResourceQuota in a specified namespace and
// selects the priority classes provides. This allows pods with the specified pods to be scheduled
// This doesn't guarantee that a pod will be scheduled as Kubernetes will also check to ensure
// that other resource quota constraints in the namespace are satisfied.
func ResourceQuotaForPriorityClassScope(name, namespace string, priorityClasses []string) *corev1.ResourceQuota {
	return &corev1.ResourceQuota{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ResourceQuota",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.ResourceQuotaSpec{
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    priorityClasses,
					},
				},
			},
		},
	}
}
