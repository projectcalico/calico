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
	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GatewayAPISpec has fields that can be used to customize our GatewayAPI support.
type GatewayAPISpec struct {
	// Reference to a custom EnvoyGateway YAML to use as the base EnvoyGateway configuration for
	// the gateway controller.  When specified, must identify a ConfigMap resource with an
	// "envoy-gateway.yaml" key whose value is the desired EnvoyGateway YAML (i.e. following the
	// same pattern as the default `envoy-gateway-config` ConfigMap).
	//
	// When not specified, the Tigera operator uses the `envoy-gateway-config` from the Envoy
	// Gateway helm chart as its base.
	//
	// Starting from that base, the Tigera operator copies and modifies the EnvoyGateway
	// resource as follows:
	//
	// 1. If not already specified, it sets the ControllerName to
	// "gateway.envoyproxy.io/gatewayclass-controller".
	//
	// 2. It configures the `tigera/envoy-gateway` and `tigera/envoy-ratelimit` images that will
	// be used (according to the current Calico version, private registry and image set
	// settings) and any pull secrets that are needed to pull those images.
	//
	// 3. It enables use of the Backend API.
	//
	// The resulting EnvoyGateway is provisioned as the `envoy-gateway-config` ConfigMap (which
	// the gateway controller then uses as its config).
	// +optional
	EnvoyGatewayConfigRef *NamespacedName `json:"envoyGatewayConfigRef,omitempty"`

	// Configures the GatewayClasses that will be available; please see GatewayClassSpec for
	// more detail.  If GatewayClasses is nil, the Tigera operator defaults to provisioning a
	// single GatewayClass named "tigera-gateway-class", without any of the detailed
	// customizations that are allowed within GatewayClassSpec.
	// +optional
	GatewayClasses []GatewayClassSpec `json:"gatewayClasses,omitempty"`

	// Allows customization of the gateway controller deployment.
	// +optional
	GatewayControllerDeployment *GatewayControllerDeployment `json:"gatewayControllerDeployment,omitempty"`

	// Allows customization of the gateway certgen job.
	// +optional
	GatewayCertgenJob *GatewayCertgenJob `json:"gatewayCertgenJob,omitempty"`

	// Configures how to manage and update Gateway API CRDs.  The default behaviour - which is
	// used when this field is not set, or is set to "PreferExisting" - is that the Tigera
	// operator will create the Gateway API CRDs if they do not already exist, but will not
	// overwrite any existing Gateway API CRDs.  This setting may be preferable if the customer
	// is using other implementations of the Gateway API concurrently with the Gateway API
	// support in Calico Enterprise.  It is then the customer's responsibility to ensure that
	// CRDs are installed that meet the needs of all the Gateway API implementations in their
	// cluster.
	//
	// Alternatively, if this field is set to "Reconcile", the Tigera operator will keep the
	// cluster's Gateway API CRDs aligned with those that it would install on a cluster that
	// does not yet have any version of those CRDs.
	// +optional
	CRDManagement *CRDManagement `json:"crdManagement,omitempty"`

	// Extensions enables and configures Tigera-built add-ons that sit on top of the
	// Gateway API data plane.  Each add-on is opt-in: an unset Extensions, an unset
	// add-on field, and an empty add-on object all leave the add-on disabled.
	// +optional
	Extensions *GatewayAPIExtensions `json:"extensions,omitempty"`
}

// GatewayAPIExtensions enables and configures Tigera-built Gateway API add-ons.
type GatewayAPIExtensions struct {
	// WAF enables and configures the Tigera Web Application Firewall (Coraza WASM
	// + applicationlayer reconcilers).  Default-off semantics: when WAF is nil,
	// when WAF.State is nil, and when WAF.State is "Disabled", the operator does
	// not render the WAF env vars or RBAC on calico-kube-controllers.  Set
	// WAF.State = "Enabled" to turn the feature on.  See design
	// `tigera/designs#25` (PMREQ-384) for the full surface.
	// +optional
	WAF *WAFExtensionSpec `json:"waf,omitempty"`
}

// WAFExtensionSpec configures the WAF Gateway API add-on.
type WAFExtensionSpec struct {
	// State turns the WAF Gateway API add-on on or off.  Default (nil or
	// "Disabled") means the operator does not render the WAF surface on
	// calico-kube-controllers.  Set to "Enabled" to opt in.
	// +optional
	State *WAFExtensionState `json:"state,omitempty"`
}

// WAFExtensionState is the on/off enum for the WAF Gateway API add-on.
// +kubebuilder:validation:Enum=Enabled;Disabled
type WAFExtensionState string

const (
	WAFExtensionStateEnabled  WAFExtensionState = "Enabled"
	WAFExtensionStateDisabled WAFExtensionState = "Disabled"
)

// IsWAFGatewayExtensionEnabled returns true if spec.extensions.waf.state == Enabled.
// Unset Extensions, unset WAF, unset State, and explicit Disabled all return false.
func (s *GatewayAPISpec) IsWAFGatewayExtensionEnabled() bool {
	if s == nil || s.Extensions == nil || s.Extensions.WAF == nil || s.Extensions.WAF.State == nil {
		return false
	}
	return *s.Extensions.WAF.State == WAFExtensionStateEnabled
}

type GatewayClassSpec struct {
	// The name of this GatewayClass.
	Name string `json:"name"`

	// Reference to a custom EnvoyProxy resource to use as the base EnvoyProxy configuration for
	// this GatewayClass.  When specified, must identify an EnvoyProxy resource.
	//
	// When not specified, the Tigera operator uses an empty EnvoyProxy resource as its base.
	//
	// Starting from that base, the Tigera operator copies and modifies the EnvoyProxy resource
	// as follows, in the order described:
	//
	// 1. It configures the `tigera/envoy-proxy` image that will be used (according to the
	// current Calico version, private registry and image set settings) and any pull secrets
	// that are needed to pull that image.
	//
	// 2. It applies customizations as specified by the following `GatewayKind`,
	// `GatewayDeployment`, `GatewayDaemonSet` and `GatewayService` fields.
	//
	// The resulting EnvoyProxy is provisioned in the `tigera-gateway` namespace, together with
	// a GatewayClass that references it.
	//
	// If a custom EnvoyProxy resource is specified and uses `EnvoyDaemonSet` instead of the
	// default `EnvoyDeployment`, deployment-related customizations will be applied within
	// `EnvoyDaemonSet` instead of within `EnvoyDeployment`.
	// +optional
	EnvoyProxyRef *NamespacedName `json:"envoyProxyRef,omitempty"`

	// Specifies whether Gateways in this class are deployed as Deployments (default) or as
	// DaemonSets.  It is an error for GatewayKind to specify a choice that is incompatible with
	// the custom EnvoyProxy, when EnvoyProxyRef is also specified.
	// +optional
	GatewayKind *GatewayKind `json:"gatewayKind,omitempty"`

	// Allows customization of Gateways when deployed as Kubernetes Deployments, for Gateways in
	// this GatewayClass.
	// +optional
	GatewayDeployment *GatewayDeployment `json:"gatewayDeployment,omitempty"`

	// Allows customization of Gateways when deployed as Kubernetes DaemonSets, for Gateways in
	// this GatewayClass.
	// +optional
	GatewayDaemonSet *GatewayDaemonSet `json:"gatewayDaemonSet,omitempty"`

	// Allows customization of gateway services, for Gateways in this GatewayClass.
	// +optional
	GatewayService *GatewayService `json:"gatewayService,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster

// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default' || self.metadata.name == 'tigera-secure'", message="resource name must be 'default'"
type GatewayAPI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GatewayAPISpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

type GatewayAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayAPI `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GatewayAPI{}, &GatewayAPIList{})
}

// GatewayControllerDeployment allows customization of the gateway controller deployment.
type GatewayControllerDeployment struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into the
	// deployment's top-level metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayControllerDeploymentSpec `json:"spec,omitempty"`
}

// GatewayControllerDeploymentSpec allows customization of the gateway controller deployment spec.
type GatewayControllerDeploymentSpec struct {
	// If non-nil, Replicas sets the number of replicas for the deployment.
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// If non-nil, MinReadySeconds sets the minReadySeconds field for the deployment.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// +optional
	Template *GatewayControllerDeploymentPodTemplate `json:"template,omitempty"`
}

// GatewayControllerDeploymentPodTemplate allows customization of the gateway controller deployment
// pod template.
type GatewayControllerDeploymentPodTemplate struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into the
	// deployment's pod template.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayControllerDeploymentPodSpec `json:"spec,omitempty"`
}

// GatewayControllerDeploymentPodSpec allows customization of the gateway controller deployment pod
// spec.
type GatewayControllerDeploymentPodSpec struct {
	// If non-nil, Affinity sets the affinity field of the deployment's pod template.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayControllerDeploymentContainer `json:"containers,omitempty"`

	// If non-nil, NodeSelector sets the node selector for where deployment pods may be
	// scheduled.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// If non-nil, TopologySpreadConstraints sets the topology spread constraints of the
	// deployment's pod template.  TopologySpreadConstraints describes how a group of pods ought
	// to spread across topology domains. Scheduler will schedule pods in a way which abides by
	// the constraints.  All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// If non-nil, Tolerations sets the tolerations field of the deployment's pod template.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// GatewayControllerDeploymentContainer allows customization of the gateway controller's resource
// requirements.
type GatewayControllerDeploymentContainer struct {
	// +kubebuilder:validation:Enum=envoy-gateway
	Name string `json:"name"`

	// If non-nil, Resources sets the ResourceRequirements of the controller's "envoy-gateway"
	// container.
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

// GatewayCertgenJob allows customization of the gateway certgen job.
type GatewayCertgenJob struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into the
	// job's top-level metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayCertgenJobSpec `json:"spec,omitempty"`
}

// GatewayCertgenJobSpec allows customization of the gateway certgen job spec.
type GatewayCertgenJobSpec struct {
	// +optional
	Template *GatewayCertgenJobPodTemplate `json:"template,omitempty"`
}

// GatewayCertgenJobPodTemplate allows customization of the gateway certgen job's pod template.
type GatewayCertgenJobPodTemplate struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into the
	// job's pod template.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayCertgenJobPodSpec `json:"spec,omitempty"`
}

// GatewayCertgenJobPodSpec allows customization of the gateway certgen job's pod spec.
type GatewayCertgenJobPodSpec struct {
	// If non-nil, Affinity sets the affinity field of the job's pod template.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayCertgenJobContainer `json:"containers,omitempty"`

	// If non-nil, NodeSelector sets the node selector for where job pods may be scheduled.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// If non-nil, Tolerations sets the tolerations field of the job's pod template.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// GatewayCertgenJobContainer allows customization of the gateway certgen job's resource
// requirements.
type GatewayCertgenJobContainer struct {
	// +kubebuilder:validation:Enum=envoy-gateway-certgen
	Name string `json:"name"`

	// If non-nil, Resources sets the ResourceRequirements of the job's "envoy-gateway-certgen"
	// container.
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

// +kubebuilder:validation:Enum=Deployment;DaemonSet
type GatewayKind string

const (
	GatewayKindDeployment GatewayKind = "Deployment"
	GatewayKindDaemonSet  GatewayKind = "DaemonSet"
)

// GatewayDeployment allows customization of Gateways when deployed as Kubernetes Deployments.
type GatewayDeployment struct {
	// +optional
	Spec *GatewayDeploymentSpec `json:"spec,omitempty"`
}

// GatewayDeploymentSpec allows customization of the spec of gateway deployments.
type GatewayDeploymentSpec struct {
	// If non-nil, Replicas sets the number of replicas for the deployment.
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// +optional
	Template *GatewayDeploymentPodTemplate `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *GatewayDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
}

// GatewayDeploymentPodTemplate allows customization of the pod template of gateway deployments.
type GatewayDeploymentPodTemplate struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into each
	// deployment's pod template.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayDeploymentPodSpec `json:"spec,omitempty"`
}

// GatewayDeploymentPodSpec allows customization of the pod spec of gateway deployments.
type GatewayDeploymentPodSpec struct {
	// If non-nil, Affinity sets the affinity field of the deployment's pod template.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayDeploymentContainer `json:"containers,omitempty"`

	// If non-nil, NodeSelector sets the node selector for where deployment pods may be
	// scheduled.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// If non-nil, TopologySpreadConstraints sets the topology spread constraints of the
	// deployment's pod template.  TopologySpreadConstraints describes how a group of pods ought
	// to spread across topology domains. Scheduler will schedule pods in a way which abides by
	// the constraints.  All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// If non-nil, Tolerations sets the tolerations field of the deployment's pod template.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// GatewayDeploymentContainer allows customization of the resource requirements of gateway
// deployments.
type GatewayDeploymentContainer struct {
	// +kubebuilder:validation:Enum=envoy
	Name string `json:"name"`

	// If non-nil, Resources sets the ResourceRequirements of the deployment's "envoy"
	// container.
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

// GatewayDeploymentStrategy allows customization of the deployment strategy for gateway
// deployments.
//
// If GatewayDeployment.Spec.Strategy is non-nil, gateway deployments are set to use a rolling
// update strategy, with the parameters specified in GatewayDeployment.Spec.Strategy.
//
// Only RollingUpdate is supported at this time so the Type field is not exposed.
type GatewayDeploymentStrategy struct {
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}

// GatewayDeployment allows customization of Gateways when deployed as Kubernetes DaemonSets.
type GatewayDaemonSet struct {
	// +optional
	Spec *GatewayDaemonSetSpec `json:"spec,omitempty"`
}

// GatewayDeploymentSpec allows customization of the spec of gateway daemonsets.
type GatewayDaemonSetSpec struct {
	// +optional
	Template *GatewayDaemonSetPodTemplate `json:"template,omitempty"`
}

// GatewayDeploymentPodTemplate allows customization of the pod template of gateway daemonsets.
type GatewayDaemonSetPodTemplate struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into each
	// daemonset's pod template.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayDaemonSetPodSpec `json:"spec,omitempty"`
}

// GatewayDaemonSetPodSpec allows customization of the pod spec of gateway daemonsets.
type GatewayDaemonSetPodSpec struct {
	// If non-nil, Affinity sets the affinity field of the daemonset's pod template.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayDaemonSetContainer `json:"containers,omitempty"`

	// If non-nil, NodeSelector sets the node selector for where daemonset pods may be
	// scheduled.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// If non-nil, TopologySpreadConstraints sets the topology spread constraints of the
	// daemonset's pod template.  TopologySpreadConstraints describes how a group of pods ought
	// to spread across topology domains. Scheduler will schedule pods in a way which abides by
	// the constraints.  All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// If non-nil, Tolerations sets the tolerations field of the daemonset's pod template.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// GatewayDaemonSetContainer allows customization of the resource requirements of gateway
// daemonsets.
type GatewayDaemonSetContainer struct {
	// +kubebuilder:validation:Enum=envoy
	Name string `json:"name"`

	// If non-nil, Resources sets the ResourceRequirements of the daemonset's "envoy"

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
	// container.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// GatewayService allows customization of the Services that front Gateways.
type GatewayService struct {
	// If non-nil, non-clashing labels and annotations from this metadata are added into the
	// each Gateway Service's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayServiceSpec `json:"spec,omitempty"`
}

// GatewayServiceSpec allows customization of the services that front gateway deployments.
//
// The LoadBalancer fields allow customization of the corresponding fields in the Kubernetes
// ServiceSpec.  These can be used for some cloud-independent control of the external load balancer
// that is provisioned for each Gateway.  For finer-grained cloud-specific control please use
// the Metadata.Annotations field in GatewayService.
type GatewayServiceSpec struct {
	// +optional
	LoadBalancerClass *string `json:"loadBalancerClass,omitempty"`

	// +optional
	AllocateLoadBalancerNodePorts *bool `json:"allocateLoadBalancerNodePorts,omitempty"`

	// +optional
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// +optional
	LoadBalancerIP *string `json:"loadBalancerIP,omitempty"`

	// Patch allows the Service for a gateway to be patched in ways that aren't more explicitly
	// supported by the fields above.  For example, the following YAML could be used to set the
	// Service's healthCheckNodePort:
	//
	//   patch:
	//     type: StrategicMerge
	//     value:
	//       spec:
	//         healthCheckNodePort: 12345
	//
	// +optional
	Patch *envoyapi.KubernetesPatchSpec `json:"patch,omitempty"`
}
