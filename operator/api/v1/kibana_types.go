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

// Kibana is the configuration for the Kibana.
type Kibana struct {
	// Spec is the specification of the Kibana.
	// +optional
	Spec *KibanaSpec `json:"spec,omitempty"`
}

type KibanaSpec struct {
	// Replicas defines the number of Kibana replicas. When set to 0, Kibana is not rendered.
	// Default: 1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// Template describes the Kibana pod that will be created.
	// +optional
	Template *KibanaPodTemplateSpec `json:"template,omitempty"`
}

// KibanaPodTemplateSpec is the Kibana's PodTemplateSpec
type KibanaPodTemplateSpec struct {
	// Spec is the Kibana's PodSpec.
	// +optional
	Spec *KibanaPodSpec `json:"spec,omitempty"`
}

// KibanaPodSpec is the Kibana Deployment's PodSpec.
type KibanaPodSpec struct {
	// InitContainers is a list of Kibana init containers.
	// If specified, this overrides the specified Kibana Deployment init containers.
	// If omitted, the Kibana Deployment will use its default values for its init containers.
	// +optional
	InitContainers []KibanaInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Kibana containers.
	// If specified, this overrides the specified Kibana Deployment containers.
	// If omitted, the Kibana Deployment will use its default values for its containers.
	// +optional
	Containers []KibanaContainer `json:"containers,omitempty"`
}

// KibanaContainer is a Kibana container.
type KibanaContainer struct {
	// Name is an enum which identifies the Kibana Deployment container by name.
	// Supported values are: kibana
	// +kubebuilder:validation:Enum=kibana
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Kibana container's resources.
	// If omitted, the Kibana will use its default value for this container's resources.
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

// KibanaInitContainer is a Kibana init container.
type KibanaInitContainer struct {
	// Name is an enum which identifies the Kibana init container by name.
	// Supported values are: key-cert-provisioner
	// +kubebuilder:validation:Enum=key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Kibana Deployment init container's resources.
	// If omitted, the Kibana Deployment will use its default value for this init container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
