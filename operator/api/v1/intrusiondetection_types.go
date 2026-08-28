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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IntrusionDetectionSpec defines the desired state of Tigera intrusion detection capabilities.
type IntrusionDetectionSpec struct {
	// ComponentResources can be used to customize the resource requirements for each component.
	// Only DeepPacketInspection is supported for this spec.
	// +optional
	ComponentResources []IntrusionDetectionComponentResource `json:"componentResources,omitempty"`

	// AnomalyDetection is now deprecated, and configuring it has no effect.
	// +optional
	AnomalyDetection AnomalyDetectionSpec `json:"anomalyDetection,omitempty"`

	// IntrusionDetectionControllerDeployment configures the IntrusionDetection Controller Deployment.
	// +optional
	IntrusionDetectionControllerDeployment *IntrusionDetectionControllerDeployment `json:"intrusionDetectionControllerDeployment,omitempty"`

	// DeepPacketInspectionDaemonset configures the DPI Daemonset
	// +optional
	DeepPacketInspectionDaemonset *DeepPacketInspectionDaemonset `json:"deepPacketInspectionDaemonset,omitempty"`
}

type DeepPacketInspectionDaemonset struct {
	// DPIDaemonsetSpec configures the DPI Daemonset
	// +optional
	Spec *DPIDaemonsetSpec `json:"spec,omitempty"`
}

type DPIDaemonsetSpec struct {
	// Template specifies DPI Daemonset Template
	// +optional
	Template *DPIDaemonsetTemplate `json:"template,omitempty"`
}

type DPIDaemonsetTemplate struct {
	// Spec specifies DPI Daemonset Template Spec
	// +optional
	Spec *DPIDaemonsetTemplateSpec `json:"spec,omitempty"`
}

type DPIDaemonsetTemplateSpec struct {
	// List of DPI Daemonset Init containers definitions
	// +kubebuilder:validation:MaxItems=1
	InitContainers []DPIDaemonsetInitContainer `json:"initContainers,omitempty"`
}

type DPIDaemonsetInitContainer struct {
	// Name is an enum that identifies the init container by its name.
	// +kubebuilder:validation:Enum=snort-rules
	Name string `json:"name"`

	// Image name for the init container
	Image string `json:"image"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the init container's resources.
	// If omitted, the default values will be used for the init container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type AnomalyDetectionSpec struct {
	// StorageClassName is now deprecated, and configuring it has no effect.
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// IntrusionDetectionStatus defines the observed state of Tigera intrusion detection capabilities.
type IntrusionDetectionStatus struct {
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

// IntrusionDetection installs the components required for Tigera intrusion detection. At most one instance
// of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type IntrusionDetection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera intrusion detection.
	Spec IntrusionDetectionSpec `json:"spec,omitempty"`
	// Most recently observed state for Tigera intrusion detection.
	Status IntrusionDetectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IntrusionDetectionList contains a list of IntrusionDetection
type IntrusionDetectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntrusionDetection `json:"items"`
}

type IntrusionDetectionComponentName string

const (
	ComponentNameDeepPacketInspection IntrusionDetectionComponentName = "DeepPacketInspection"
)

// The ComponentResource struct associates a ResourceRequirements with a component by name
type IntrusionDetectionComponentResource struct {
	// ComponentName is an enum which identifies the component
	// +kubebuilder:validation:Enum=DeepPacketInspection
	ComponentName IntrusionDetectionComponentName `json:"componentName"`
	// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
	ResourceRequirements *corev1.ResourceRequirements `json:"resourceRequirements"`
}

// IntrusionDetectionControllerDeployment is the configuration for the IntrusionDetectionController Deployment.
type IntrusionDetectionControllerDeployment struct {
	// Spec is the specification of the IntrusionDetectionController Deployment.
	// +optional
	Spec *IntrusionDetectionControllerDeploymentSpec `json:"spec,omitempty"`
}

// IntrusionDetectionControllerDeploymentSpec defines configuration for the IntrusionDetectionController Deployment.
type IntrusionDetectionControllerDeploymentSpec struct {
	// Template describes the IntrusionDetectionController Deployment pod that will be created.
	// +optional
	Template *IntrusionDetectionControllerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// IntrusionDetectionControllerDeploymentPodTemplateSpec is the IntrusionDetectionController Deployment's PodTemplateSpec
type IntrusionDetectionControllerDeploymentPodTemplateSpec struct {
	// Spec is the IntrusionDetectionController Deployment's PodSpec.
	// +optional
	Spec *IntrusionDetectionControllerDeploymentPodSpec `json:"spec,omitempty"`
}

// IntrusionDetectionControllerDeploymentPodSpec is the IntrusionDetectionController Deployment's PodSpec.
type IntrusionDetectionControllerDeploymentPodSpec struct {
	// InitContainers is a list of IntrusionDetectionController init containers.
	// If specified, this overrides the specified IntrusionDetectionController Deployment init containers.
	// If omitted, the IntrusionDetectionController Deployment will use its default values for its init containers.
	// +optional
	InitContainers []IntrusionDetectionControllerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of IntrusionDetectionController containers.
	// If specified, this overrides the specified IntrusionDetectionController Deployment containers.
	// If omitted, the IntrusionDetectionController Deployment will use its default values for its containers.
	// +optional
	Containers []IntrusionDetectionControllerDeploymentContainer `json:"containers,omitempty"`
}

// IntrusionDetectionControllerDeploymentContainer is a IntrusionDetectionController Deployment container.
type IntrusionDetectionControllerDeploymentContainer struct {
	// Name is an enum which identifies the IntrusionDetectionController Deployment container by name.
	// Supported values are: controller, webhooks-processor
	// +kubebuilder:validation:Enum=controller;webhooks-processor
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named IntrusionDetectionController Deployment container's resources.
	// If omitted, the IntrusionDetection Deployment will use its default value for this container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}

// IntrusionDetectionControllerDeploymentInitContainer is a IntrusionDetectionController Deployment init container.
type IntrusionDetectionControllerDeploymentInitContainer struct {
	// Name is an enum which identifies the IntrusionDetectionController Deployment init container by name.
	// Supported values are: intrusion-detection-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=intrusion-detection-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named IntrusionDetectionController Deployment init container's resources.
	// If omitted, the IntrusionDetectionController Deployment will use its default value for this init container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

func init() {
	SchemeBuilder.Register(&IntrusionDetection{}, &IntrusionDetectionList{})
}
