// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.
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

// LinseedDeployment is the configuration for the linseed Deployment.
type LinseedDeployment struct {

	// Spec is the specification of the linseed Deployment.
	// +optional
	Spec *LinseedDeploymentSpec `json:"spec,omitempty"`
}

// LinseedDeploymentSpec defines configuration for the linseed Deployment.
type LinseedDeploymentSpec struct {

	// Template describes the linseed Deployment pod that will be created.
	// +optional
	Template *LinseedDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// LinseedDeploymentPodTemplateSpec is the linseed Deployment's PodTemplateSpec
type LinseedDeploymentPodTemplateSpec struct {

	// Spec is the linseed Deployment's PodSpec.
	// +optional
	Spec *LinseedDeploymentPodSpec `json:"spec,omitempty"`
}

// LinseedDeploymentPodSpec is the linseed Deployment's PodSpec.
type LinseedDeploymentPodSpec struct {
	// InitContainers is a list of linseed init containers.
	// If specified, this overrides the specified linseed Deployment init containers.
	// If omitted, the linseed Deployment will use its default values for its init containers.
	// +optional
	InitContainers []LinseedDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of linseed containers.
	// If specified, this overrides the specified linseed Deployment containers.
	// If omitted, the linseed Deployment will use its default values for its containers.
	// +optional
	Containers []LinseedDeploymentContainer `json:"containers,omitempty"`
}

// LinseedDeploymentContainer is a linseed Deployment container.
type LinseedDeploymentContainer struct {
	// Name is an enum which identifies the linseed Deployment container by name.
	// Supported values are: tigera-linseed
	// +kubebuilder:validation:Enum=tigera-linseed
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named linseed Deployment container's resources.
	// If omitted, the linseed Deployment will use its default value for this container's resources.
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

// LinseedDeploymentInitContainer is a linseed Deployment init container.
type LinseedDeploymentInitContainer struct {
	// Name is an enum which identifies the linseed Deployment init container by name.
	// Supported values are: tigera-secure-linseed-token-tls-key-cert-provisioner,tigera-secure-linseed-cert-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-secure-linseed-token-tls-key-cert-provisioner;tigera-secure-linseed-cert-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named linseed Deployment init container's resources.
	// If omitted, the linseed Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
