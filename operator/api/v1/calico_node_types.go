// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
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

// CalicoNodeDaemonSetContainer is a calico-node DaemonSet container.
type CalicoNodeDaemonSetContainer struct {
	// Name is an enum which identifies the calico-node DaemonSet container by name.
	// Supported values are: calico-node
	// +kubebuilder:validation:Enum=calico-node
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-node DaemonSet container's resources.
	// If omitted, the calico-node DaemonSet will use its default value for this container's resources.
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

	// StartupProbe allows customization of the startup probe timing parameters.
	// The probe handler is set by the operator.
	// +optional
	StartupProbe *ProbeOverride `json:"startupProbe,omitempty"`
}

// CalicoNodeDaemonSetInitContainer is a calico-node DaemonSet init container.
type CalicoNodeDaemonSetInitContainer struct {
	// Name is an enum which identifies the calico-node DaemonSet init container by name.
	// Supported values are: install-cni, cni-plugins, hostpath-init, flexvol-driver, ebpf-bootstrap, node-certs-key-cert-provisioner, calico-node-prometheus-server-tls-key-cert-provisioner, mount-bpffs (deprecated, replaced by ebpf-bootstrap)
	// +kubebuilder:validation:Enum=install-cni;cni-plugins;hostpath-init;flexvol-driver;ebpf-bootstrap;node-certs-key-cert-provisioner;calico-node-prometheus-server-tls-key-cert-provisioner;mount-bpffs
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-node DaemonSet init container's resources.
	// If omitted, the calico-node DaemonSet will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// CalicoNodeDaemonSetPodSpec is the calico-node DaemonSet's PodSpec.
type CalicoNodeDaemonSetPodSpec struct {
	// InitContainers is a list of calico-node init containers.
	// If specified, this overrides the specified calico-node DaemonSet init containers.
	// If omitted, the calico-node DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []CalicoNodeDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of calico-node containers.
	// If specified, this overrides the specified calico-node DaemonSet containers.
	// If omitted, the calico-node DaemonSet will use its default values for its containers.
	// +optional
	Containers []CalicoNodeDaemonSetContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the calico-node pods.
	// If specified, this overrides any affinity that may be set on the calico-node DaemonSet.
	// If omitted, the calico-node DaemonSet will use its default value for affinity.
	// WARNING: Please note that this field will override the default calico-node DaemonSet affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// NodeSelector is the calico-node pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-node DaemonSet nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-node DaemonSet will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-node DaemonSet nodeSelector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the calico-node pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the calico-node DaemonSet.
	// If omitted, the calico-node DaemonSet will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-node DaemonSet tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`

	// DNSPolicy is the DNS policy for the calico-node pods. Defaults to Default, which uses the node's
	// own resolver, since calico-node runs before cluster DNS is reachable.
	// +kubebuilder:validation:Enum="";Default;ClusterFirst;ClusterFirstWithHostNet;None
	// +optional
	DNSPolicy *v1.DNSPolicy `json:"dnsPolicy,omitempty"`

	// DNSConfig allows customization of the DNS configuration for the calico-node pods.
	// +optional
	DNSConfig *v1.PodDNSConfig `json:"dnsConfig,omitempty"`
}

// CalicoNodeDaemonSetPodTemplateSpec is the calico-node DaemonSet's PodTemplateSpec
type CalicoNodeDaemonSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the calico-node DaemonSet's PodSpec.
	// +optional
	Spec *CalicoNodeDaemonSetPodSpec `json:"spec,omitempty"`
}

// CalicoNodeDaemonSet is the configuration for the calico-node DaemonSet.
type CalicoNodeDaemonSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the DaemonSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the calico-node DaemonSet.
	// +optional
	Spec *CalicoNodeDaemonSetSpec `json:"spec,omitempty"`
}

// CalicoNodeDaemonSetSpec defines configuration for the calico-node DaemonSet.
type CalicoNodeDaemonSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created DaemonSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the calico-node DaemonSet.
	// If omitted, the calico-node DaemonSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the calico-node DaemonSet pod that will be created.
	// +optional
	Template *CalicoNodeDaemonSetPodTemplateSpec `json:"template,omitempty"`
}
