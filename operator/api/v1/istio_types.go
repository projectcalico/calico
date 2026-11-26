// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IstiodDeploymentPodSpec defines the pod spec for customizing the Istiod Deployment.
type IstiodDeploymentPodSpec struct {
	// Affinity specifies the affinity for the deployment.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// NodeSelector specifies the node affinity for the deployment.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources specifies the compute resources required for the deployment.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations specifies the tolerations for the deployment.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// IstiodDeploymentSpecTemplate defines the template for customizing the Istiod Deployment.
type IstiodDeploymentSpecTemplate struct {
	// Spec allows users to specify custom fields for the Istiod Deployment.
	// +optional
	Spec *IstiodDeploymentPodSpec `json:"spec,omitempty"`
}

// IstiodDeploymentSpec defines the spec for customizing the Istiod Deployment.
type IstiodDeploymentSpec struct {
	// Template allows users to specify custom fields for the Istiod Deployment.
	// +optional
	Template *IstiodDeploymentSpecTemplate `json:"template,omitempty"`
}

// IstiodDeployment defines customized settings for the Istio deployment.
type IstiodDeployment struct {
	// Spec allows users to specify custom fields for the Istiod Deployment.
	// +optional
	Spec *IstiodDeploymentSpec `json:"spec,omitempty"`
}

// IstioCNIDaemonsetPodSpec defines the pod spec for customizing the Istio CNI Daemonset.
type IstioCNIDaemonsetPodSpec struct {
	// Affinity specifies the affinity for the deployment.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// NodeSelector specifies the node affinity for the deployment.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources specifies the compute resources required for the deployment.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations specifies the tolerations for the deployment.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// IstioCNIDaemonsetSpecTemplate defines the template for customizing the Istio CNI Daemonset.
type IstioCNIDaemonsetSpecTemplate struct {
	// Spec allows users to specify custom fields for the Istio CNI Daemonset.
	// +optional
	Spec *IstioCNIDaemonsetPodSpec `json:"spec,omitempty"`
}

// IstioCNIDaemonsetSpec defines the spec for customizing the Istio CNI Daemonset.
type IstioCNIDaemonsetSpec struct {
	// Template allows users to specify custom fields for the Istio CNI Daemonset.
	// +optional
	Template *IstioCNIDaemonsetSpecTemplate `json:"template,omitempty"`
}

// IstioCNIDaemonset defines customized settings for the Istio CNI plugin.
type IstioCNIDaemonset struct {
	// Spec allows users to specify custom fields for the Istio CNI Daemonset.
	// +optional
	Spec *IstioCNIDaemonsetSpec `json:"spec,omitempty"`
}

// ZTunnelDaemonsetPodSpec defines the pod spec for customizing the ZTunnel Daemonset.
type ZTunnelDaemonsetPodSpec struct {
	// Affinity specifies the affinity for the deployment.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// NodeSelector specifies the node affinity for the deployment.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources specifies the compute resources required for the deployment.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations specifies the tolerations for the deployment.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// ZTunnelDaemonsetSpecTemplate defines the template for customizing the ZTunnel Daemonset.
type ZTunnelDaemonsetSpecTemplate struct {
	// Spec allows users to specify custom fields for the ZTunnel Daemonset.
	// +optional
	Spec *ZTunnelDaemonsetPodSpec `json:"spec,omitempty"`
}

// ZTunnelDaemonsetSpec defines the spec for customizing the ZTunnel Daemonset.
type ZTunnelDaemonsetSpec struct {
	// Template allows users to specify custom fields for the ZTunnel Daemonset.
	// +optional
	Template *ZTunnelDaemonsetSpecTemplate `json:"template,omitempty"`
}

// ZTunnelDaemonset defines customized settings for the ZTunnelDaemonset component.
type ZTunnelDaemonset struct {
	// Spec allows users to specify custom fields for the ZTunnel Daemonset.
	// +optional
	Spec *ZTunnelDaemonsetSpec `json:"spec,omitempty"`
}

// IstioCertificateAuthority selects the certificate authority istiod signs workload
// certificates with. At most one member may be set; an empty value means the same
// as unset.
// +kubebuilder:validation:MaxProperties=1
type IstioCertificateAuthority struct {
	// OperatorManaged is the explicit form of the default: the operator generates
	// the CA and manages its lifecycle.
	// +optional
	OperatorManaged *IstioOperatorManagedCA `json:"operatorManaged,omitempty"`
	// Secret names a Secret in the operator namespace that holds a customer CA, in
	// either Istio's plug-in CA layout (ca-cert.pem, ca-key.pem, cert-chain.pem,
	// root-cert.pem) or the kubernetes.io/tls layout (tls.crt, tls.key, ca.crt).
	// The Secret must have the label operator.tigera.io/istio-ca: "true",
	// because the operator copies its private key into the Istio namespace.
	// +optional
	Secret *IstioCASecret `json:"secret,omitempty"`
}

// IstioOperatorManagedCA configures the certificate authority the operator
// generates and manages. It has no settings yet.
type IstioOperatorManagedCA struct{}

// IstioCASecret references a Secret in the operator namespace by name.
type IstioCASecret struct {
	// Name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// IstioTrustAnchors configures the root certificates ztunnel trusts in addition to
// this cluster's own root.
type IstioTrustAnchors struct {
	// Additional lists static root certificates to trust, for meshes that include
	// clusters Calico does not manage.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	Additional []IstioTrustAnchor `json:"additional,omitempty"`
}

// IstioTrustAnchor is one static root certificate. Exactly one member must be set.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type IstioTrustAnchor struct {
	// Secret names a Secret in the operator namespace whose root-cert.pem key holds
	// the certificate.
	// +optional
	Secret *IstioCASecret `json:"secret,omitempty"`
	// PEM is the certificate in PEM form.
	// +optional
	// +kubebuilder:validation:MinLength=1
	PEM string `json:"pem,omitempty"`
}

// IstioSpec defines the desired state of Istio
type IstioSpec struct {
	// IstiodDeployment defines the resource requirements and node selector for the Istio deployment.
	// +optional
	IstiodDeployment *IstiodDeployment `json:"istiod,omitempty"`
	// IstioCNIDaemonset defines the resource requirements for the Istio CNI plugin.
	// +optional
	IstioCNIDaemonset *IstioCNIDaemonset `json:"istioCNI,omitempty"`
	// ZTunnelDaemonset defines the resource requirements for the ZTunnelDaemonset component.
	// +optional
	ZTunnelDaemonset *ZTunnelDaemonset `json:"ztunnel,omitempty"`
	// WaypointLogging controls whether L7 logging is enabled on every Gateway
	// using the istio-waypoint GatewayClass. When Enabled (the default), the
	// operator injects an l7-collector sidecar into each waypoint pod via
	// class-level defaults. When Disabled, no sidecar is injected and the
	// associated EnvoyFilters are not created. Allowed values are Enabled or
	// Disabled.
	// +optional
	WaypointLogging *LogCollectionStatusType `json:"waypointLogging,omitempty"`
	// DSCPMark define the value of the DSCP mark done by Felix and recognised by Istio CNI for Transparent
	// NetworkPolicies.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:validation:Type=integer
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Pattern=`^.*`
	// +kubebuilder:default=23
	DSCPMark *numorstring.DSCP `json:"dscpMark,omitempty"`
	// CertificateAuthority selects the certificate authority istiod signs workload
	// certificates with. At most one member may be set. When unset, the operator
	// generates and manages the CA.
	// +optional
	CertificateAuthority *IstioCertificateAuthority `json:"certificateAuthority,omitempty"`
	// TrustAnchors configures the root certificates ztunnel trusts in addition to
	// this cluster's own root. When unset, no static roots are added.
	// +optional
	TrustAnchors *IstioTrustAnchors `json:"trustAnchors,omitempty"`
	// TrustDomain is the trust domain of workload identities, rendered to istiod's
	// meshConfig.trustDomain and ztunnel's TRUST_DOMAIN. It is one or more
	// dot-separated DNS-1123 labels, optionally ending in a dot, and must be
	// identical in every cluster of a mesh. Defaults to cluster.local.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.?$`
	TrustDomain *string `json:"trustDomain,omitempty"`
}

// +kubebuilder:validation:Enum=Enabled;Disabled
type LogCollectionStatusType string

const (
	L7LogCollectionDisabled LogCollectionStatusType = "Disabled"
	L7LogCollectionEnabled  LogCollectionStatusType = "Enabled"
)

// IstioStatus defines the observed state of Istio
type IstioStatus struct {
	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'", message="resource name must be 'default'"

// Istio is the Schema for the istios API
type Istio struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IstioSpec   `json:"spec,omitempty"`
	Status IstioStatus `json:"status,omitempty"`
}

// WaypointLoggingEnabled reports whether waypoint L7 logging should be rendered
// for this Istio CR. It defaults to true when the field is unset, and is the
// single source of truth shared by the renderer (which gates the l7-collector
// sidecar + EnvoyFilters) and the policy-sync predicate (which gates
// policySyncPathPrefix), so the two never diverge. A nil receiver reports false.
func (i *Istio) WaypointLoggingEnabled() bool {
	if i == nil {
		return false
	}
	wl := i.Spec.WaypointLogging
	return wl == nil || *wl != L7LogCollectionDisabled
}

// +kubebuilder:object:root=true

// IstioList contains a list of Istio resources.
type IstioList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Istio `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Istio{}, &IstioList{})
}
