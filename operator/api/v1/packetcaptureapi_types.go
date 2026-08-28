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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PacketCaptureAPISpec defines configuration for the Packet Capture API.
type PacketCaptureAPISpec struct {
	// PacketCaptureAPIDeployment configures the PacketCaptureAPI Deployment.
	// +optional
	PacketCaptureAPIDeployment *PacketCaptureAPIDeployment `json:"packetCaptureAPIDeployment,omitempty"`
}

// PacketCaptureAPIDeployment is the configuration for the PacketCaptureAPI Deployment.
type PacketCaptureAPIDeployment struct {
	// Spec is the specification of the PacketCaptureAPI Deployment.
	// +optional
	Spec *PacketCaptureAPIDeploymentSpec `json:"spec,omitempty"`
}

// PacketCaptureAPIDeploymentSpec defines configuration for the PacketCaptureAPI Deployment.
type PacketCaptureAPIDeploymentSpec struct {
	// Template describes the PacketCaptureAPI Deployment pod that will be created.
	// +optional
	Template *PacketCaptureAPIDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// PacketCaptureAPIDeploymentPodTemplateSpec is the PacketCaptureAPI Deployment's PodTemplateSpec
type PacketCaptureAPIDeploymentPodTemplateSpec struct {
	// Spec is the PacketCaptureAPI Deployment's PodSpec.
	// +optional
	Spec *PacketCaptureAPIDeploymentPodSpec `json:"spec,omitempty"`
}

// PacketCaptureAPIDeploymentPodSpec is the PacketCaptureAPI Deployment's PodSpec.
type PacketCaptureAPIDeploymentPodSpec struct {
	// InitContainers is a list of PacketCaptureAPI init containers.
	// If specified, this overrides the specified PacketCaptureAPI Deployment init containers.
	// If omitted, the PacketCaptureAPI Deployment will use its default values for its init containers.
	// +optional
	InitContainers []PacketCaptureAPIDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of PacketCaptureAPI containers.
	// If specified, this overrides the specified PacketCaptureAPI Deployment containers.
	// If omitted, the PacketCaptureAPI Deployment will use its default values for its containers.
	// +optional
	Containers []PacketCaptureAPIDeploymentContainer `json:"containers,omitempty"`
}

// PacketCaptureAPIDeploymentContainer is a PacketCaptureAPI Deployment container.
type PacketCaptureAPIDeploymentContainer struct {
	// Name is an enum which identifies the PacketCaptureAPI Deployment container by name.
	// Supported values are: tigera-packetcapture-server
	// +kubebuilder:validation:Enum=tigera-packetcapture-server
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PacketCaptureAPI Deployment container's resources.
	// If omitted, the PacketCaptureAPI Deployment will use its default value for this container's resources.
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

// PacketCaptureAPIDeploymentInitContainer is a PacketCaptureAPI Deployment init container.
type PacketCaptureAPIDeploymentInitContainer struct {
	// Name is an enum which identifies the PacketCaptureAPI Deployment init container by name.
	// Supported values are: tigera-packetcapture-server-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-packetcapture-server-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PacketCaptureAPI Deployment init container's resources.
	// If omitted, the PacketCaptureAPI Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// PacketCaptureAPI is used to configure the resource requirement for PacketCaptureAPI deployment. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'", message="resource name must be 'tigera-secure'"
type PacketCaptureAPI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the PacketCaptureAPI.
	Spec PacketCaptureAPISpec `json:"spec,omitempty"`
	// Most recently observed state for the PacketCaptureAPI.
	Status PacketCaptureAPIStatus `json:"status,omitempty"`
}

// PacketCaptureAPIStatus defines the observed state of the Packet Capture API.
type PacketCaptureAPIStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// PacketCaptureAPIList contains a list of PacketCaptureAPI
type PacketCaptureAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PacketCaptureAPI `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PacketCaptureAPI{}, &PacketCaptureAPIList{})
}
