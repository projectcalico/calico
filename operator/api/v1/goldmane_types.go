// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'", message="resource name must be 'default'"
type Goldmane struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GoldmaneSpec `json:"spec,omitempty"`

	Status GoldmaneStatus `json:"status,omitempty"`
}

type GoldmaneSpec struct {
	GoldmaneDeployment *GoldmaneDeployment `json:"goldmaneDeployment,omitempty"`

	// MetricsPort configures the port that Goldmane uses to serve Prometheus metrics.
	// When set to a non-zero value, Goldmane will expose a /metrics endpoint on the given port.
	// Set to zero to disable metrics. If omitted, metrics are disabled.
	// +optional
	MetricsPort *int32 `json:"metricsPort,omitempty"`
}

// +kubebuilder:object:root=true

// GoldmaneList contains a list of Whisker.
type GoldmaneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Goldmane `json:"items"`
}

// GoldmaneStatus defines the observed state of Goldmane
type GoldmaneStatus struct {
	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

func init() {
	SchemeBuilder.Register(&Goldmane{}, &GoldmaneList{})
}
