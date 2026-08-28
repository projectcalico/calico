/*
Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

const (
	TigeraStatusReady    = "Ready"
	TigeraStatusDegraded = "Degraded"
)

// TigeraStatusSpec defines the desired state of TigeraStatus
type TigeraStatusSpec struct{}

// TigeraStatusStatus defines the observed state of TigeraStatus
type TigeraStatusStatus struct {
	// Conditions represents the latest observed set of conditions for this component. A component may be one or more of
	// Available, Progressing, or Degraded.
	Conditions []TigeraStatusCondition `json:"conditions"`
}

// +kubebuilder:object:root=true

// TigeraStatus represents the most recently observed status for Calico or a Calico Enterprise functional area.
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type=='Available')].status",description="Whether the component running and stable."
// +kubebuilder:printcolumn:name="Progressing",type="string",JSONPath=".status.conditions[?(@.type=='Progressing')].status",description="Whether the component is processing changes."
// +kubebuilder:printcolumn:name="Degraded",type="string",JSONPath=".status.conditions[?(@.type=='Degraded')].status",description="Whether the component is degraded."
// +kubebuilder:printcolumn:name="Since",type="date",JSONPath=".status.conditions[?(@.type=='Available')].lastTransitionTime",description="The time the component's Available status last changed."
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type=='Degraded')].message",description="Error message when the component is degraded.",priority=0
type TigeraStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TigeraStatusSpec   `json:"spec,omitempty"`
	Status TigeraStatusStatus `json:"status,omitempty"`
}

// ConditionStatus represents the status of a particular condition. A condition may be one of: True, False, Unknown.
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// StatusConditionType is a type of condition that may apply to a particular component.
type StatusConditionType string

const (
	// Available indicates that the component is healthy.
	ComponentAvailable StatusConditionType = "Available"

	// Progressing means that the component is in the process of being installed or upgraded.
	ComponentProgressing StatusConditionType = "Progressing"

	// Degraded means the component is not operating as desired and user action is required.
	ComponentDegraded StatusConditionType = "Degraded"

	// Ready indicates that the component is healthy and ready.it is identical to Available and used in Status conditions for CRs.
	ComponentReady StatusConditionType = "Ready"
)

// TigeraStatusCondition represents a condition attached to a particular component.
// +k8s:deepcopy-gen=true
type TigeraStatusCondition struct {
	// The type of condition. May be Available, Progressing, or Degraded.
	Type StatusConditionType `json:"type"`

	// The status of the condition. May be True, False, or Unknown.
	Status ConditionStatus `json:"status"`

	// The timestamp representing the start time for the current status.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// A brief reason explaining the condition.
	Reason string `json:"reason,omitempty"`

	// Optionally, a detailed message providing additional context.
	Message string `json:"message,omitempty"`

	// observedGeneration represents the generation that the condition was set based upon.
	// For instance, if generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the instance.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true

// TigeraStatusList contains a list of TigeraStatus
type TigeraStatusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TigeraStatus `json:"items"`
}

// TigeraStatusReason represents the reason for a particular condition.
type TigeraStatusReason string

const (
	AllObjectsAvailable       TigeraStatusReason = "AllObjectsAvailable"
	ResourceNotReady          TigeraStatusReason = "ResourceNotReady"
	PodFailure                TigeraStatusReason = "PodFailure"
	CertificateError          TigeraStatusReason = "CertificateError"
	CertificateReadError      TigeraStatusReason = "CertificateReadError"
	InvalidConfigurationError TigeraStatusReason = "InvalidConfigurationError"
	ResourceCreateError       TigeraStatusReason = "ResourceCreateError"
	ResourceMigrationError    TigeraStatusReason = "ResourceMigrationError"
	ResourceNotFound          TigeraStatusReason = "ResourceNotFound"
	ResourcePatchError        TigeraStatusReason = "ResourcePatchError"
	ResourceReadError         TigeraStatusReason = "ResourceReadError"
	ResourceRenderingError    TigeraStatusReason = "ResourceRenderingError"
	ResourceScalingError      TigeraStatusReason = "ResourceScalingError"
	ResourceUpdateError       TigeraStatusReason = "ResourceUpdateError"
	ResourceValidationError   TigeraStatusReason = "ResourceValidationError"
	MigrationError            TigeraStatusReason = "MigrationError"
	InternalServerError       TigeraStatusReason = "InternalServerError"
	NotApplicable             TigeraStatusReason = "NotApplicable"
	UpgradeError              TigeraStatusReason = "UpgradeError"
	Unknown                   TigeraStatusReason = "Unknown"
	ImageSetError             TigeraStatusReason = "ImageSetError"
)

func init() {
	SchemeBuilder.Register(&TigeraStatus{}, &TigeraStatusList{})
}

// Available returns true if the TigeraStatus has a condition of type "Available" with status "True".
func (ts *TigeraStatus) Available() bool {
	if ts != nil && ts.Status.Conditions != nil {
		for _, condition := range ts.Status.Conditions {
			if condition.Type == ComponentAvailable && condition.Status == ConditionTrue {
				return true
			}
		}
	}
	return false
}
