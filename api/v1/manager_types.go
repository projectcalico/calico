// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

// ManagerSpec defines configuration for the Calico Enterprise manager GUI.
type ManagerSpec struct {
	// ManagerDeployment configures the Manager Deployment.
	// +optional
	ManagerDeployment *ManagerDeployment `json:"managerDeployment,omitempty"`
}

// ManagerDeployment is the configuration for the Manager Deployment.
type ManagerDeployment struct {
	// Spec is the specification of the Manager Deployment.
	// +optional
	Spec *ManagerDeploymentSpec `json:"spec,omitempty"`
}

// ManagerDeploymentSpec defines configuration for the Manager Deployment.
type ManagerDeploymentSpec struct {
	// Template describes the Manager Deployment pod that will be created.
	// +optional
	Template *ManagerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ManagerDeploymentPodTemplateSpec is the Manager Deployment's PodTemplateSpec
type ManagerDeploymentPodTemplateSpec struct {
	// Spec is the Manager Deployment's PodSpec.
	// +optional
	Spec *ManagerDeploymentPodSpec `json:"spec,omitempty"`
}

// ManagerDeploymentPodSpec is the Manager Deployment's PodSpec.
type ManagerDeploymentPodSpec struct {
	// InitContainers is a list of Manager init containers.
	// If specified, this overrides the specified Manager Deployment init containers.
	// If omitted, the Manager Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ManagerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Manager containers.
	// If specified, this overrides the specified Manager Deployment containers.
	// If omitted, the Manager Deployment will use its default values for its containers.
	// +optional
	Containers []ManagerDeploymentContainer `json:"containers,omitempty"`
}

// ManagerDeploymentContainer is a Manager Deployment container.
type ManagerDeploymentContainer struct {
	// Name is an enum which identifies the Manager Deployment container by name.
	// Supported values are: calico-voltron, calico-manager, calico-ui-apis, calico-dashboard-api, tigera-voltron (deprecated), tigera-manager (deprecated), tigera-ui-apis (deprecated), tigera-es-proxy (deprecated)
	// +kubebuilder:validation:Enum=calico-voltron;calico-manager;calico-ui-apis;calico-dashboard-api;tigera-voltron;tigera-manager;tigera-ui-apis
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Manager Deployment container's resources.
	// If omitted, the Manager Deployment will use its default value for this container's resources.
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

// ManagerDeploymentInitContainer is a Manager Deployment init container.
type ManagerDeploymentInitContainer struct {
	// Name is an enum which identifies the Manager Deployment init container by name.
	// Supported values are: manager-tls-key-cert-provisioner, internal-manager-tls-key-cert-provisioner, calico-voltron-linseed-tls-key-cert-provisioner, tigera-voltron-linseed-tls-key-cert-provisioner (deprecated)
	// +kubebuilder:validation:Enum=manager-tls-key-cert-provisioner;internal-manager-tls-key-cert-provisioner;calico-voltron-linseed-tls-key-cert-provisioner;tigera-voltron-linseed-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Manager Deployment init container's resources.
	// If omitted, the Manager Deployment will use its default value for this init container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ManagerStatus defines the observed state of the Calico Enterprise manager GUI.
type ManagerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Manager installs the Calico Enterprise manager graphical user interface. At most one instance
// of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type Manager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Calico Enterprise manager.
	Spec ManagerSpec `json:"spec,omitempty"`
	// Most recently observed state for the Calico Enterprise manager.
	Status ManagerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ManagerList contains a list of Manager
type ManagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Manager `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Manager{}, &ManagerList{})
}
