// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyRecommendationSpec defines configuration for the Calico Enterprise Policy Recommendation
// service.
type PolicyRecommendationSpec struct {
	// PolicyRecommendation configures the PolicyRecommendation Deployment.
	// +optional
	PolicyRecommendationDeployment *PolicyRecommendationDeployment `json:"policyRecommendationDeployment,omitempty"`
}

// PolicyRecommendationDeployment is the configuration for the PolicyRecommendation Deployment.
type PolicyRecommendationDeployment struct {
	// Spec is the specification of the PolicyRecommendation Deployment.
	// +optional
	Spec *PolicyRecommendationDeploymentSpec `json:"spec,omitempty"`
}

// PolicyRecommendationDeploymentSpec defines configuration for the PolicyRecommendation Deployment.
type PolicyRecommendationDeploymentSpec struct {
	// Template describes the PolicyRecommendation Deployment pod that will be created.
	// +optional
	Template *PolicyRecommendationDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// PolicyRecommendationDeploymentPodTemplateSpec is the PolicyRecommendation Deployment's PodTemplateSpec
type PolicyRecommendationDeploymentPodTemplateSpec struct {
	// Spec is the PolicyRecommendation Deployment's PodSpec.
	// +optional
	Spec *PolicyRecommendationDeploymentPodSpec `json:"spec,omitempty"`
}

// PolicyRecommendationDeploymentPodSpec is the PolicyRecommendation Deployment's PodSpec.
type PolicyRecommendationDeploymentPodSpec struct {
	// InitContainers is a list of PolicyRecommendation init containers.
	// If specified, this overrides the specified PolicyRecommendation Deployment init containers.
	// If omitted, the PolicyRecommendation Deployment will use its default values for its init containers.
	// +optional
	InitContainers []PolicyRecommendationDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of PolicyRecommendation containers.
	// If specified, this overrides the specified PolicyRecommendation Deployment containers.
	// If omitted, the PolicyRecommendation Deployment will use its default values for its containers.
	// +optional
	Containers []PolicyRecommendationDeploymentContainer `json:"containers,omitempty"`
}

// PolicyRecommendationDeploymentContainer is a PolicyRecommendation Deployment container.
type PolicyRecommendationDeploymentContainer struct {
	// Name is an enum which identifies the PolicyRecommendation Deployment container by name.
	// Supported values are: policy-recommendation-controller
	// +kubebuilder:validation:Enum=policy-recommendation-controller
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PolicyRecommendation Deployment container's resources.
	// If omitted, the PolicyRecommendation Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}

// PolicyRecommendationDeploymentInitContainer is a PolicyRecommendation Deployment init container.
type PolicyRecommendationDeploymentInitContainer struct {
	// Name is an enum which identifies the PolicyRecommendation Deployment init container by name.
	// +kubebuilder:validation:Enum=policy-recommendation-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PolicyRecommendation Deployment init container's resources.
	// If omitted, the PolicyRecommendation Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// PolicyRecommendationStatus defines the observed state of Tigera policy recommendation.
type PolicyRecommendationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// PolicyRecommendation is the Schema for the policy recommendation API. At most one instance
// of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'", message="resource name must be 'tigera-secure'"
type PolicyRecommendation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyRecommendationSpec   `json:"spec,omitempty"`
	Status PolicyRecommendationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyRecommendationList contains a list of Monitor
type PolicyRecommendationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyRecommendation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyRecommendation{}, &PolicyRecommendationList{})
}
