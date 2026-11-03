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

// GuardianDeployment is the configuration for the guardian Deployment.
type GuardianDeployment struct {

	// Spec is the specification of the guardian Deployment.
	// +optional
	Spec *GuardianDeploymentSpec `json:"spec,omitempty"`
}

// GuardianDeploymentSpec defines configuration for the guardian Deployment.
type GuardianDeploymentSpec struct {

	// Template describes the guardian Deployment pod that will be created.
	// +optional
	Template *GuardianDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// GuardianDeploymentPodTemplateSpec is the guardian Deployment's PodTemplateSpec
type GuardianDeploymentPodTemplateSpec struct {

	// Spec is the guardian Deployment's PodSpec.
	// +optional
	Spec *GuardianDeploymentPodSpec `json:"spec,omitempty"`
}

// GuardianDeploymentPodSpec is the guardian Deployment's PodSpec.
type GuardianDeploymentPodSpec struct {
	// InitContainers is a list of guardian init containers.
	// If specified, this overrides the specified guardian Deployment init containers.
	// If omitted, the guardian Deployment will use its default values for its init containers.
	// +optional
	InitContainers []GuardianDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of guardian containers.
	// If specified, this overrides the specified guardian Deployment containers.
	// If omitted, the guardian Deployment will use its default values for its containers.
	// +optional
	Containers []GuardianDeploymentContainer `json:"containers,omitempty"`
}

// GuardianDeploymentContainer is a guardian Deployment container.
type GuardianDeploymentContainer struct {
	// Name is an enum which identifies the guardian Deployment container by name.
	// Supported values are: tigera-guardian
	// +kubebuilder:validation:Enum=tigera-guardian
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named guardian Deployment container's resources.
	// If omitted, the guardian Deployment will use its default value for this container's resources.
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

// GuardianDeploymentInitContainer is a guardian Deployment init container.
type GuardianDeploymentInitContainer struct {
	// Name is an enum which identifies the guardian Deployment init container by name.
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named guardian Deployment init container's resources.
	// If omitted, the guardian Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
