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

// FluentBitDaemonSet is the configuration for the Fluent Bit DaemonSet.
type FluentBitDaemonSet struct {

	// Spec is the specification of the Fluent Bit DaemonSet.
	// +optional
	Spec *FluentBitDaemonSetSpec `json:"spec,omitempty"`
}

// FluentBitDaemonSetSpec defines configuration for the Fluent Bit DaemonSet.
type FluentBitDaemonSetSpec struct {

	// Template describes the Fluent Bit DaemonSet pod that will be created.
	// +optional
	Template *FluentBitDaemonSetPodTemplateSpec `json:"template,omitempty"`
}

// FluentBitDaemonSetPodTemplateSpec is the Fluent Bit DaemonSet's PodTemplateSpec
type FluentBitDaemonSetPodTemplateSpec struct {

	// Spec is the Fluent Bit DaemonSet's PodSpec.
	// +optional
	Spec *FluentBitDaemonSetPodSpec `json:"spec,omitempty"`
}

// FluentBitDaemonSetPodSpec is the Fluent Bit DaemonSet's PodSpec.
type FluentBitDaemonSetPodSpec struct {
	// InitContainers is a list of Fluent Bit DaemonSet init containers.
	// If specified, this overrides the specified Fluent Bit DaemonSet init containers.
	// If omitted, the Fluent Bit DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []FluentBitDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Fluent Bit DaemonSet containers.
	// If specified, this overrides the specified Fluent Bit DaemonSet containers.
	// If omitted, the Fluent Bit DaemonSet will use its default values for its containers.
	// +optional
	Containers []FluentBitDaemonSetContainer `json:"containers,omitempty"`
}

// FluentBitDaemonSetContainer is a Fluent Bit DaemonSet container.
type FluentBitDaemonSetContainer struct {
	// Name is an enum which identifies the Fluent Bit DaemonSet container by name.
	// Supported values are: calico-fluent-bit (or the deprecated alias fluentd, kept
	// for one release so existing FluentdDaemonSet overrides continue to validate).
	// +kubebuilder:validation:Enum=calico-fluent-bit;fluentd
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Fluent Bit DaemonSet container's resources.
	// If omitted, the Fluent Bit DaemonSet will use its default value for this container's resources.
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

// FluentBitDaemonSetInitContainer is a Fluent Bit DaemonSet init container.
type FluentBitDaemonSetInitContainer struct {
	// Name is an enum which identifies the Fluent Bit DaemonSet init container by name.
	// Supported values are: calico-fluent-bit-tls-key-cert-provisioner (or the deprecated
	// alias tigera-fluentd-prometheus-tls-key-cert-provisioner, kept for one release so
	// existing FluentdDaemonSet overrides continue to validate).
	// +kubebuilder:validation:Enum=calico-fluent-bit-tls-key-cert-provisioner;tigera-fluentd-prometheus-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Fluent Bit DaemonSet init container's resources.
	// If omitted, the Fluent Bit DaemonSet will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
