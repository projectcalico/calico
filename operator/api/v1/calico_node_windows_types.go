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

// CalicoNodeWindowsDaemonSetContainer is a calico-node-windows DaemonSet container.
type CalicoNodeWindowsDaemonSetContainer struct {
	// Name is an enum which identifies the calico-node-windows DaemonSet container by name.
	// Supported values are: node, felix, confd
	// calico-node-windows is allowed because it was previously allowed.
	// +kubebuilder:validation:Enum=calico-node-windows;node;felix;confd
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named DaemonSet container's resources.
	// If omitted, the DaemonSet will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
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

// CalicoNodeWindowsDaemonSetInitContainer is a calico-node-windows DaemonSet init container.
type CalicoNodeWindowsDaemonSetInitContainer struct {
	// Name is an enum which identifies the calico-node-windows DaemonSet init container by name.
	// Supported values are: install-cni;hostpath-init, flexvol-driver, node-certs-key-cert-provisioner, calico-node-windows-prometheus-server-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=install-cni;hostpath-init;flexvol-driver;node-certs-key-cert-provisioner;calico-node-windows-prometheus-server-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-node-windows DaemonSet init container's resources.
	// If omitted, the calico-node-windows DaemonSet will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// CalicoNodeWindowsDaemonSetPodSpec is the calico-node-windows DaemonSet's PodSpec.
type CalicoNodeWindowsDaemonSetPodSpec struct {
	// InitContainers is a list of calico-node-windows init containers.
	// If specified, this overrides the specified calico-node-windows DaemonSet init containers.
	// If omitted, the calico-node-windows DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []CalicoNodeWindowsDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of calico-node-windows containers.
	// If specified, this overrides the specified calico-node-windows DaemonSet containers.
	// If omitted, the calico-node-windows DaemonSet will use its default values for its containers.
	// +optional
	Containers []CalicoNodeWindowsDaemonSetContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the calico-node-windows pods.
	// If specified, this overrides any affinity that may be set on the calico-node-windows DaemonSet.
	// If omitted, the calico-node-windows DaemonSet will use its default value for affinity.
	// WARNING: Please note that this field will override the default calico-node-windows DaemonSet affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// NodeSelector is the calico-node-windows pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-node-windows DaemonSet nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-node-windows DaemonSet will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-node-windows DaemonSet nodeSelector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the calico-node-windows pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the calico-node-windows DaemonSet.
	// If omitted, the calico-node-windows DaemonSet will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-node-windows DaemonSet tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// CalicoNodeWindowsDaemonSetPodTemplateSpec is the calico-node-windows DaemonSet's PodTemplateSpec
type CalicoNodeWindowsDaemonSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the calico-node-windows DaemonSet's PodSpec.
	// +optional
	Spec *CalicoNodeWindowsDaemonSetPodSpec `json:"spec,omitempty"`
}

// CalicoNodeWindowsDaemonSet is the configuration for the calico-node-windows DaemonSet.
type CalicoNodeWindowsDaemonSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the DaemonSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the calico-node-windows DaemonSet.
	// +optional
	Spec *CalicoNodeWindowsDaemonSetSpec `json:"spec,omitempty"`
}

// CalicoNodeWindowsDaemonSetSpec defines configuration for the calico-node-windows DaemonSet.
type CalicoNodeWindowsDaemonSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created DaemonSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the calico-node-windows DaemonSet.
	// If omitted, the calico-node-windows DaemonSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the calico-node-windows DaemonSet pod that will be created.
	// +optional
	Template *CalicoNodeWindowsDaemonSetPodTemplateSpec `json:"template,omitempty"`
}
