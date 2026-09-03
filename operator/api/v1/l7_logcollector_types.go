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

// L7LogCollectorDaemonSet is the configuration for the L7LogCollector DaemonSet.
type L7LogCollectorDaemonSet struct {

	// Spec is the specification of the L7LogCollector DaemonSet.
	// +optional
	Spec *L7LogCollectorDaemonSetSpec `json:"spec,omitempty"`
}

// L7LogCollectorDaemonSetSpec defines configuration for the L7LogCollector DaemonSet.
type L7LogCollectorDaemonSetSpec struct {

	// Template describes the L7LogCollector DaemonSet pod that will be created.
	// +optional
	Template *L7LogCollectorDaemonSetPodTemplateSpec `json:"template,omitempty"`
}

// L7LogCollectorDaemonSetPodTemplateSpec is the L7LogCollector DaemonSet's PodTemplateSpec
type L7LogCollectorDaemonSetPodTemplateSpec struct {

	// Spec is the L7LogCollector DaemonSet's PodSpec.
	// +optional
	Spec *L7LogCollectorDaemonSetPodSpec `json:"spec,omitempty"`
}

// L7LogCollectorDaemonSetPodSpec is the L7LogCollector DaemonSet's PodSpec.
type L7LogCollectorDaemonSetPodSpec struct {
	// InitContainers is a list of L7LogCollector DaemonSet init containers.
	// If specified, this overrides the specified L7LogCollector DaemonSet init containers.
	// If omitted, the L7LogCollector DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []L7LogCollectorDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of L7LogCollector DaemonSet containers.
	// If specified, this overrides the specified L7LogCollector DaemonSet containers.
	// If omitted, the L7LogCollector DaemonSet will use its default values for its containers.
	// +optional
	Containers []L7LogCollectorDaemonSetContainer `json:"containers,omitempty"`
}

// L7LogCollectorDaemonSetContainer is a L7LogCollector DaemonSet container.
type L7LogCollectorDaemonSetContainer struct {
	// Name is an enum which identifies the L7LogCollector DaemonSet container by name.
	// Supported values are: l7-collector, envoy-proxy, dikastes
	// +kubebuilder:validation:Enum=l7-collector;envoy-proxy;dikastes
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named L7LogCollector DaemonSet container's resources.
	// If omitted, the L7LogCollector DaemonSet will use its default value for this container's resources.
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

// L7LogCollectorDaemonSetInitContainer is a L7LogCollector DaemonSet init container.
type L7LogCollectorDaemonSetInitContainer struct {
	// Name is an enum which identifies the L7LogCollector DaemonSet init container by name.
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named L7LogCollector DaemonSet init container's resources.
	// If omitted, the L7LogCollector DaemonSet will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
