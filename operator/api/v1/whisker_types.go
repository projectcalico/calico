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

type NotificationMode string

const (
	Disabled NotificationMode = "Disabled"
	Enabled  NotificationMode = "Enabled"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'", message="resource name must be 'default'"
type Whisker struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WhiskerSpec   `json:"spec,omitempty"`
	Status WhiskerStatus `json:"status,omitempty"`
}

type WhiskerSpec struct {
	WhiskerDeployment *WhiskerDeployment `json:"whiskerDeployment,omitempty"`

	// Default: Enabled
	// This setting enables calls to an external API to retrieve notification banner text in the Whisker UI.
	// Allowed values are Enabled or Disabled. Defaults to Enabled.
	// +optional
	Notifications *NotificationMode `json:"notifications,omitempty"`
}

// +kubebuilder:object:root=true

// WhiskerList contains a list of Whisker.
type WhiskerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Whisker `json:"items"`
}

// WhiskerStatus defines the observed state of Whisker
type WhiskerStatus struct {
	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

func init() {
	SchemeBuilder.Register(&Whisker{}, &WhiskerList{})
}
