// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package v1

import (
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PodDisruptionBudgetOverride allows overriding select fields on an operator-managed
// PodDisruptionBudget. The PDB's selector, name, and namespace are managed by the
// operator and cannot be overridden.
type PodDisruptionBudgetOverride struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the PodDisruptionBudget.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the PodDisruptionBudget.
	// +optional
	Spec *PodDisruptionBudgetOverrideSpec `json:"spec,omitempty"`
}

// PodDisruptionBudgetOverrideSpec defines the desired state of an operator-managed PodDisruptionBudget.
// +kubebuilder:validation:XValidation:rule="!(has(self.minAvailable) && has(self.maxUnavailable))",message="minAvailable and maxUnavailable are mutually exclusive"
type PodDisruptionBudgetOverrideSpec struct {
	// MinAvailable is the minimum number of pods (as an integer or percentage) that
	// must remain available during a disruption. Mutually exclusive with MaxUnavailable.
	// +optional
	MinAvailable *intstr.IntOrString `json:"minAvailable,omitempty"`

	// MaxUnavailable is the maximum number of pods (as an integer or percentage) that
	// can be unavailable during a disruption. Mutually exclusive with MinAvailable.
	// If neither MinAvailable nor MaxUnavailable is set, the operator applies its
	// default (MaxUnavailable=1 for calico-typha).
	// +optional
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`

	// UnhealthyPodEvictionPolicy defines when unhealthy pods should be considered
	// for eviction. Defaults to IfHealthyBudget (the Kubernetes default) when unset.
	// See https://kubernetes.io/docs/tasks/run-application/configure-pdb/#unhealthy-pod-eviction-policy.
	// +kubebuilder:validation:Enum=IfHealthyBudget;AlwaysAllow
	// +optional
	UnhealthyPodEvictionPolicy *policyv1.UnhealthyPodEvictionPolicyType `json:"unhealthyPodEvictionPolicy,omitempty"`
}
