// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
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
)

// DexDeployment is the configuration for the Dex Deployment.
type DexDeployment struct {

	// Spec is the specification of the Dex Deployment.
	// +optional
	Spec *DexDeploymentSpec `json:"spec,omitempty"`
}

// DexDeploymentSpec defines configuration for the Dex Deployment.
type DexDeploymentSpec struct {

	// Template describes the Dex Deployment pod that will be created.
	// +optional
	Template *DexDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// DexDeploymentPodTemplateSpec is the Dex Deployment's PodTemplateSpec
type DexDeploymentPodTemplateSpec struct {

	// Spec is the Dex Deployment's PodSpec.
	// +optional
	Spec *DexDeploymentPodSpec `json:"spec,omitempty"`
}

// DexDeploymentPodSpec is the Dex Deployment's PodSpec.
type DexDeploymentPodSpec struct {
	// InitContainers is a list of Dex init containers.
	// If specified, this overrides the specified Dex Deployment init containers.
	// If omitted, the Dex Deployment will use its default values for its init containers.
	// +optional
	InitContainers []DexDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Dex containers.
	// If specified, this overrides the specified Dex Deployment containers.
	// If omitted, the Dex Deployment will use its default values for its containers.
	// +optional
	Containers []DexDeploymentContainer `json:"containers,omitempty"`
}

// DexDeploymentContainer is a Dex Deployment container.
type DexDeploymentContainer struct {
	// Name is an enum which identifies the Dex Deployment container by name.
	// Supported values are: tigera-dex
	// +kubebuilder:validation:Enum=tigera-dex
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Dex Deployment container's resources.
	// If omitted, the Dex Deployment will use its default value for this container's resources.
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

// DexDeploymentInitContainer is a Dex Deployment init container.
type DexDeploymentInitContainer struct {
	// Name is an enum which identifies the Dex Deployment init container by name.
	// Supported values are: tigera-dex-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-dex-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Dex Deployment init container's resources.
	// If omitted, the Dex Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
