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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Installation configures an installation of Calico or Calico Enterprise. At most one instance
// of this resource is supported. It must be named "default". The Installation API installs core networking
// and network policy components, and provides general install-time configuration.
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default' || self.metadata.name == 'tigera-secure' || self.metadata.name == 'overlay'", message="resource name must be 'default', 'tigera-secure', or 'overlay'"
type Installation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Calico or Calico Enterprise installation.
	Spec InstallationSpec `json:"spec,omitempty"`
	// Most recently observed state for the Calico or Calico Enterprise installation.
	Status InstallationStatus `json:"status,omitempty"`
}

// InstallationSpec defines configuration for a Calico or Calico Enterprise installation.
type InstallationSpec struct {
	// Variant is the product to install - one of Calico or CalicoEnterprise.
	// TigeraSecureEnterprise is also accepted as a deprecated alias for CalicoEnterprise.
	// Default: Calico
	// +optional
	// +kubebuilder:validation:Enum=Calico;CalicoEnterprise;TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`

	// Registry is the default Docker registry used for component Docker images.
	// If specified then the given value must end with a slash character (`/`) and all images will be pulled from this registry.
	// If not specified then the default registries will be used. A special case value, UseDefault, is
	// supported to explicitly specify the default registries will be used.
	//
	// Image format:
	//    `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>`
	//
	// This option allows configuring the `<registry>` portion of the above format.
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePath allows for the path part of an image to be specified. If specified
	// then the specified value will be used as the image path for each image. If not specified
	// or empty, the default for each image will be used.
	// A special case value, UseDefault, is supported to explicitly specify the default
	// image path will be used for each image.
	//
	// Image format:
	//    `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>`
	//
	// This option allows configuring the `<imagePath>` portion of the above format.
	// +optional
	ImagePath string `json:"imagePath,omitempty"`

	// ImagePrefix allows for the prefix part of an image to be specified. If specified
	// then the given value will be used as a prefix on each image. If not specified
	// or empty, no prefix will be used.
	// A special case value, UseDefault, is supported to explicitly specify the default
	// image prefix will be used for each image.
	//
	// Image format:
	//    `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>`
	//
	// This option allows configuring the `<imagePrefix>` portion of the above format.
	// +optional
	ImagePrefix string `json:"imagePrefix,omitempty"`

	// ImagePullSecrets is an array of references to container registry pull secrets to use. These are
	// applied to all images to be pulled.
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// ImagePullPolicy is the pull policy applied to containers in pods rendered by the operator
	// that do not explicitly set their own pull policy. If unset, defaults to IfNotPresent.
	// This is useful in air-gapped environments where images are pre-loaded onto nodes and
	// must not be re-pulled from a remote registry.
	// +optional
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	ImagePullPolicy *v1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// KubernetesProvider specifies a particular provider of the Kubernetes platform and enables provider-specific configuration.
	// If the specified value is empty, the Operator will attempt to automatically determine the current provider.
	// If the specified value is not empty, the Operator will still attempt auto-detection, but
	// will additionally compare the auto-detected value to the specified value to confirm they match.
	// +optional
	// +kubebuilder:validation:Enum="";EKS;GKE;AKS;OpenShift;DockerEnterprise;RKE2;TKG;Kind;
	KubernetesProvider Provider `json:"kubernetesProvider,omitempty"`

	// CNI specifies the CNI that will be used by this installation.
	// +optional
	CNI *CNISpec `json:"cni,omitempty"`

	// CalicoNetwork specifies networking configuration options for Calico.
	// +optional
	CalicoNetwork *CalicoNetworkSpec `json:"calicoNetwork,omitempty"`

	// Deprecated. Please use Installation.Spec.TyphaDeployment instead.
	// TyphaAffinity allows configuration of node affinity characteristics for Typha pods.
	// +optional
	TyphaAffinity *TyphaAffinity `json:"typhaAffinity,omitempty"`

	// ControlPlaneNodeSelector is used to select control plane nodes on which to run Calico
	// components. This is globally applied to all resources created by the operator excluding daemonsets.
	// +optional
	ControlPlaneNodeSelector map[string]string `json:"controlPlaneNodeSelector,omitempty"`

	// ControlPlaneTolerations specify tolerations which are then globally applied to all resources
	// created by the operator.
	// +optional
	ControlPlaneTolerations []v1.Toleration `json:"controlPlaneTolerations,omitempty"`

	// ControlPlaneReplicas defines how many replicas of the control plane core components will be deployed.
	// This field applies to all control plane components that support High Availability. Defaults to 2.
	// +optional
	ControlPlaneReplicas *int32 `json:"controlPlaneReplicas,omitempty"`

	// NodeMetricsPort specifies which port calico/node serves prometheus metrics on. By default, metrics are not enabled.
	// If specified, this overrides any FelixConfiguration resources which may exist. If omitted, then
	// prometheus metrics may still be configured through FelixConfiguration.
	// +optional
	NodeMetricsPort *int32 `json:"nodeMetricsPort,omitempty"`

	// TyphaMetricsPort specifies which port calico/typha serves prometheus metrics on. By default, metrics are not enabled.
	// +optional
	TyphaMetricsPort *int32 `json:"typhaMetricsPort,omitempty"`

	// FlexVolumePath optionally specifies a custom path for FlexVolume. If not specified, FlexVolume will be
	// enabled by default. If set to 'None', FlexVolume will be disabled. The default is based on the
	// kubernetesProvider.
	// +optional
	FlexVolumePath string `json:"flexVolumePath,omitempty"`

	// KubeletVolumePluginPath optionally specifies enablement of Calico CSI plugin. If not specified,
	// CSI will be enabled by default. If set to 'None', CSI will be disabled.
	// Default: /var/lib/kubelet
	// +optional
	KubeletVolumePluginPath string `json:"kubeletVolumePluginPath,omitempty"`

	// NodeUpdateStrategy can be used to customize the desired update strategy, such as the MaxUnavailable
	// field.
	// +optional
	NodeUpdateStrategy appsv1.DaemonSetUpdateStrategy `json:"nodeUpdateStrategy,omitempty"`

	// Deprecated. Please use CalicoNodeDaemonSet, TyphaDeployment, and KubeControllersDeployment.
	// ComponentResources can be used to customize the resource requirements for each component.
	// Node, Typha, and KubeControllers are supported for installations.
	// +optional
	ComponentResources []ComponentResource `json:"componentResources,omitempty"`

	// CertificateManagement configures pods to submit a CertificateSigningRequest to the certificates.k8s.io/v1 API in order
	// to obtain TLS certificates. This feature requires that you bring your own CSR signing and approval process, otherwise
	// pods will be stuck during initialization.
	// +optional
	CertificateManagement *CertificateManagement `json:"certificateManagement,omitempty"`

	// TLSCipherSuites defines the cipher suite list that the TLS protocol should use during secure communication.
	// +optional
	TLSCipherSuites TLSCipherSuites `json:"tlsCipherSuites,omitempty"`

	// Deprecated. NonPrivileged is deprecated and will be removed from the API in a future release.
	// Enabling this field is not supported and will cause errors.
	// NonPrivileged configures Calico to be run in non-privileged containers as non-root users where possible.
	// +optional
	NonPrivileged *NonPrivilegedType `json:"nonPrivileged,omitempty"`

	// CalicoNodeDaemonSet configures the calico-node DaemonSet. If used in
	// conjunction with the deprecated ComponentResources, then these overrides take precedence.
	// +optional
	CalicoNodeDaemonSet *CalicoNodeDaemonSet `json:"calicoNodeDaemonSet,omitempty"`

	// CSINodeDriverDaemonSet configures the csi-node-driver DaemonSet.
	// +optional
	CSINodeDriverDaemonSet *CSINodeDriverDaemonSet `json:"csiNodeDriverDaemonSet,omitempty"`

	// CalicoKubeControllersDeployment configures the calico-kube-controllers Deployment. If used in
	// conjunction with the deprecated ComponentResources, then these overrides take precedence.
	// +optional
	CalicoKubeControllersDeployment *CalicoKubeControllersDeployment `json:"calicoKubeControllersDeployment,omitempty"`

	// TyphaDeployment configures the typha Deployment. If used in conjunction with the deprecated
	// ComponentResources or TyphaAffinity, then these overrides take precedence.
	// +optional
	TyphaDeployment *TyphaDeployment `json:"typhaDeployment,omitempty"`

	// TyphaPodDisruptionBudget configures the PodDisruptionBudget for the calico-typha
	// Deployment. Fields left unset fall back to the operator's defaults. The PDB's
	// selector is managed by the operator and cannot be overridden.
	// +optional
	TyphaPodDisruptionBudget *PodDisruptionBudgetOverride `json:"typhaPodDisruptionBudget,omitempty"`

	// Deprecated. The CalicoWindowsUpgradeDaemonSet is deprecated and will be removed from the API in the future.
	// CalicoWindowsUpgradeDaemonSet configures the calico-windows-upgrade DaemonSet.
	CalicoWindowsUpgradeDaemonSet *CalicoWindowsUpgradeDaemonSet `json:"calicoWindowsUpgradeDaemonSet,omitempty"`

	// CalicoNodeWindowsDaemonSet configures the calico-node-windows DaemonSet.
	CalicoNodeWindowsDaemonSet *CalicoNodeWindowsDaemonSet `json:"calicoNodeWindowsDaemonSet,omitempty"`

	// Deprecated. FIPS mode is no longer supported. Setting fipsMode to Enabled marks the
	// installation degraded.
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +optional
	FIPSMode *FIPSMode `json:"fipsMode,omitempty"`

	// Logging Configuration for Components
	// +optional
	Logging *Logging `json:"logging,omitempty"`

	// Windows Configuration
	// +optional
	WindowsNodes *WindowsNodeSpec `json:"windowsNodes,omitempty"`

	// Kubernetes Service CIDRs. Specifying this is required when using Calico for Windows.
	// +optional
	ServiceCIDRs []string `json:"serviceCIDRs,omitempty"`

	// Azure is used to configure azure provider specific options.
	// +optional
	Azure *Azure `json:"azure,omitempty"`

	// Proxy is used to configure the HTTP(S) proxy settings that will be applied to Tigera containers that connect
	// to destinations outside the cluster. It is expected that NO_PROXY is configured such that destinations within
	// the cluster (including the API server) are exempt from proxying.
	// +optional
	Proxy *Proxy `json:"proxy,omitempty"`

	// NetworkPolicy configures how the operator manages the NetworkPolicies and GlobalNetworkPolicies
	// it installs to protect the Calico components it manages.
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`
}

// BPFNetworkBootstrapType defines how the initial networking configuration is executed.
type BPFNetworkBootstrapType string

const (
	BPFNetworkBootstrapEnabled  BPFNetworkBootstrapType = "Enabled"
	BPFNetworkBootstrapDisabled BPFNetworkBootstrapType = "Disabled"
)

// KubeProxyManagementType specifies whether kube-proxy management is enabled.
type KubeProxyManagementType string

const (
	KubeProxyManagementEnabled  KubeProxyManagementType = "Enabled"
	KubeProxyManagementDisabled KubeProxyManagementType = "Disabled"
)

// +kubebuilder:validation:Enum=TLS_AES_256_GCM_SHA384;TLS_CHACHA20_POLY1305_SHA256;TLS_AES_128_GCM_SHA256;TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;TLS_RSA_WITH_AES_256_GCM_SHA384;TLS_RSA_WITH_AES_128_GCM_SHA256;TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
type TLSCipher string

func (c TLSCipher) String() string {
	return string(c)
}

const (
	// TLS 1.3
	TLS_AES_256_GCM_SHA384       TLSCipher = "TLS_AES_256_GCM_SHA384"
	TLS_CHACHA20_POLY1305_SHA256 TLSCipher = "TLS_CHACHA20_POLY1305_SHA256"
	TLS_AES_128_GCM_SHA256       TLSCipher = "TLS_AES_128_GCM_SHA256"

	// TLS 1.2
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       TLSCipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         TLSCipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   TLSCipher = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLSCipher = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         TLSCipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       TLSCipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	TLS_RSA_WITH_AES_256_GCM_SHA384               TLSCipher = "TLS_RSA_WITH_AES_256_GCM_SHA384"
	TLS_RSA_WITH_AES_128_GCM_SHA256               TLSCipher = "TLS_RSA_WITH_AES_128_GCM_SHA256"
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          TLSCipher = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            TLSCipher = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            TLSCipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
)

type TLSCipherSuite struct {
	// This should be a valid TLS cipher suite name.
	// +optional
	Name *TLSCipher `json:"name"`
}

type TLSCipherSuites []TLSCipherSuite

// ToString returns a comma-separated string of cipher suite names.
func (s TLSCipherSuites) ToString() string {
	if len(s) == 0 {
		return ""
	}
	names := make([]string, len(s))
	for i, suite := range s {
		names[i] = suite.Name.String()
	}
	return strings.Join(names, ",")
}

type Azure struct {
	// PolicyMode determines whether the "control-plane" label is applied to namespaces. It offers two options: Default and Manual.
	// The Default option adds the "control-plane" label to the required namespaces.
	// The Manual option does not apply the "control-plane" label to any namespace.
	// Default: Default
	// +optional
	// +kubebuilder:validation:Enum=Default;Manual
	// +kubebuilder:default:=Default
	PolicyMode *PolicyMode `json:"policyMode,omitempty"`
}

type PolicyMode string

const (
	PolicyModeDefault PolicyMode = "Default"
	PolicyModeManual  PolicyMode = "Manual"
)

type Logging struct {
	// Customized logging specification for calico-cni plugin
	// +optional
	CNI *CNILogging `json:"cni,omitempty"`
}

type CNILogging struct {
	// Default: Info
	// +optional
	LogSeverity *LogLevel `json:"logSeverity,omitempty"`

	// Default: 100Mi
	// +optional
	LogFileMaxSize *resource.Quantity `json:"logFileMaxSize,omitempty"`

	// Default: 30 (days)
	// +optional
	LogFileMaxAgeDays *uint32 `json:"logFileMaxAgeDays,omitempty"`

	// Default: 10
	// +optional
	LogFileMaxCount *uint32 `json:"logFileMaxCount,omitempty"`
}

type FIPSMode string

const (
	FIPSModeEnabled  FIPSMode = "Enabled"
	FIPSModeDisabled FIPSMode = "Disabled"
)

// Deprecated. Please use TyphaDeployment instead.
// TyphaAffinity allows configuration of node affinity characteristics for Typha pods.
type TyphaAffinity struct {
	// NodeAffinity describes node affinity scheduling rules for typha.
	// +optional
	NodeAffinity *NodeAffinity `json:"nodeAffinity,omitempty"`
}

// NodeAffinity is similar to *v1.NodeAffinity, but allows us to limit available schedulers.
type NodeAffinity struct {
	// The scheduler will prefer to schedule pods to nodes that satisfy
	// the affinity expressions specified by this field, but it may choose
	// a node that violates one or more of the expressions.
	// +optional
	PreferredDuringSchedulingIgnoredDuringExecution []v1.PreferredSchedulingTerm `json:"preferredDuringSchedulingIgnoredDuringExecution,omitempty"`

	// WARNING: Please note that if the affinity requirements specified by this field are not met at
	// scheduling time, the pod will NOT be scheduled onto the node.
	// There is no fallback to another affinity rules with this setting.
	// This may cause networking disruption or even catastrophic failure!
	// PreferredDuringSchedulingIgnoredDuringExecution should be used for affinity
	// unless there is a specific well understood reason to use RequiredDuringSchedulingIgnoredDuringExecution and
	// you can guarantee that the RequiredDuringSchedulingIgnoredDuringExecution will always have sufficient nodes to satisfy the requirement.
	// NOTE: RequiredDuringSchedulingIgnoredDuringExecution is set by default for AKS nodes,
	// to avoid scheduling Typhas on virtual-nodes.
	// If the affinity requirements specified by this field cease to be met
	// at some point during pod execution (e.g. due to an update), the system
	// may or may not try to eventually evict the pod from its node.
	// +optional
	RequiredDuringSchedulingIgnoredDuringExecution *v1.NodeSelector `json:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
}

// ComponentName represents a single component.
//
// One of: Node, Typha, KubeControllers
type ComponentName string

const (
	ComponentNameNode            ComponentName = "Node"
	ComponentNameNodeWindows     ComponentName = "NodeWindows"
	ComponentNameFelixWindows    ComponentName = "FelixWindows"
	ComponentNameConfdWindows    ComponentName = "ConfdWindows"
	ComponentNameTypha           ComponentName = "Typha"
	ComponentNameKubeControllers ComponentName = "KubeControllers"
)

// Deprecated. Please use component resource config fields in Installation.Spec instead.
// The ComponentResource struct associates a ResourceRequirements with a component by name
type ComponentResource struct {
	// ComponentName is an enum which identifies the component
	// +kubebuilder:validation:Enum=Node;Typha;KubeControllers;NodeWindows;FelixWindows;ConfdWindows
	ComponentName ComponentName `json:"componentName"`

	// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
	ResourceRequirements *v1.ResourceRequirements `json:"resourceRequirements"`
}

// Provider represents a particular provider or flavor of Kubernetes. Valid options
// are: EKS, GKE, AKS, RKE2, OpenShift, DockerEnterprise, TKG, Kind.
type Provider string

var (
	ProviderNone      Provider = ""
	ProviderEKS       Provider = "EKS"
	ProviderGKE       Provider = "GKE"
	ProviderAKS       Provider = "AKS"
	ProviderRKE2      Provider = "RKE2"
	ProviderOpenShift Provider = "OpenShift"
	ProviderDockerEE  Provider = "DockerEnterprise"
	ProviderTKG       Provider = "TKG"
	ProviderKind      Provider = "Kind"
)

func (p Provider) IsNone() bool {
	return p == ProviderNone
}

func (p Provider) IsAKS() bool {
	return p == ProviderAKS
}

func (p Provider) IsDockerEE() bool {
	return p == ProviderDockerEE
}

func (p Provider) IsEKS() bool {
	return p == ProviderEKS
}

func (p Provider) IsGKE() bool {
	return p == ProviderGKE
}

func (p Provider) IsOpenShift() bool {
	return p == ProviderOpenShift
}

func (p Provider) IsRKE2() bool {
	return p == ProviderRKE2
}

func (p Provider) IsTKG() bool {
	return p == ProviderTKG
}

func (p Provider) IsKind() bool {
	return p == ProviderKind
}

// ProductVariant represents the variant of the product.
//
// One of: Calico, CalicoEnterprise.
// TigeraSecureEnterprise is a deprecated alias for CalicoEnterprise.
type ProductVariant string

var (
	Calico           ProductVariant = "Calico"
	CalicoEnterprise ProductVariant = "CalicoEnterprise"

	// Deprecated: Use CalicoEnterprise instead.
	TigeraSecureEnterprise ProductVariant = "TigeraSecureEnterprise"
)

// IsEnterprise returns true if the variant is an enterprise variant (either CalicoEnterprise or TigeraSecureEnterprise).
func (v ProductVariant) IsEnterprise() bool {
	return v == CalicoEnterprise || v == TigeraSecureEnterprise
}

// NonPrivilegedType specifies whether Calico runs as permissioned or not
//
// One of: Enabled, Disabled
type NonPrivilegedType string

const (
	NonPrivilegedEnabled  NonPrivilegedType = "Enabled"
	NonPrivilegedDisabled NonPrivilegedType = "Disabled"
)

// ContainerIPForwardingType specifies whether the CNI config for container ip forwarding is enabled.
type ContainerIPForwardingType string

const (
	ContainerIPForwardingEnabled  ContainerIPForwardingType = "Enabled"
	ContainerIPForwardingDisabled ContainerIPForwardingType = "Disabled"
)

// LinuxPodInterfaceType specifies the type of virtual device the Calico CNI plugin
// creates for the pod-side interface on Linux nodes.
//
// One of: Veth, Netkit
// +kubebuilder:validation:Enum=Veth;Netkit
type LinuxPodInterfaceType string

const (
	LinuxPodInterfaceVeth   LinuxPodInterfaceType = "Veth"
	LinuxPodInterfaceNetkit LinuxPodInterfaceType = "Netkit"
)

// HostPortsType specifies host port support.
//
// One of: Enabled, Disabled
type HostPortsType string

const (
	HostPortsEnabled  HostPortsType = "Enabled"
	HostPortsDisabled HostPortsType = "Disabled"
)

var HostPortsTypes []HostPortsType = []HostPortsType{
	HostPortsEnabled,
	HostPortsDisabled,
}

var HostPortsTypesString []string = []string{
	HostPortsEnabled.String(),
	HostPortsDisabled.String(),
}

// MultiInterfaceMode describes the method of providing multiple pod interfaces.
//
// One of: None, Multus
type MultiInterfaceMode string

func (m MultiInterfaceMode) Value() string {
	return strings.ToLower(string(m))
}

const (
	MultiInterfaceModeNone   MultiInterfaceMode = "None"
	MultiInterfaceModeMultus MultiInterfaceMode = "Multus"
)

func HostPortsTypePtr(h HostPortsType) *HostPortsType {
	return &h
}

func (nt HostPortsType) String() string {
	return string(nt)
}

// BGPOption describes the mode of BGP to use.
//
// One of: Enabled, Disabled
type BGPOption string

func BGPOptionPtr(b BGPOption) *BGPOption {
	return &b
}

// ClusterRoutingMode describes the mode of cluster routing.
// +kubebuilder:validation:Enum=BIRD;Felix
type ClusterRoutingMode string

const (
	ClusterRoutingModeBIRD  ClusterRoutingMode = "BIRD"
	ClusterRoutingModeFelix ClusterRoutingMode = "Felix"
)

const (
	BGPEnabled  BGPOption = "Enabled"
	BGPDisabled BGPOption = "Disabled"
)

// LinuxDataplaneOption controls which dataplane is to be used on Linux nodes.
//
// One of: Iptables, BPF, VPP, Nftables
// +kubebuilder:validation:Enum=Iptables;BPF;VPP;Nftables;
type LinuxDataplaneOption string

const (
	LinuxDataplaneIptables LinuxDataplaneOption = "Iptables"
	LinuxDataplaneBPF      LinuxDataplaneOption = "BPF"
	LinuxDataplaneVPP      LinuxDataplaneOption = "VPP"
	LinuxDataplaneNftables LinuxDataplaneOption = "Nftables"
)

// +kubebuilder:validation:Enum=HNS;Disabled
type WindowsDataplaneOption string

const (
	WindowsDataplaneDisabled WindowsDataplaneOption = "Disabled"
	WindowsDataplaneHNS      WindowsDataplaneOption = "HNS"
)

type Sysctl struct {
	// +kubebuilder:validation:Enum=net.ipv4.tcp_keepalive_intvl;net.ipv4.tcp_keepalive_probes;net.ipv4.tcp_keepalive_time
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CalicoNetworkSpec specifies configuration options for Calico provided pod networking.
type CalicoNetworkSpec struct {
	// LinuxDataplane is used to select the dataplane used for Linux nodes. In particular, it
	// causes the operator to add required mounts and environment variables for the particular dataplane.
	// If not specified, iptables mode is used.
	// Default: Iptables
	// +optional
	LinuxDataplane *LinuxDataplaneOption `json:"linuxDataplane,omitempty"`

	// WindowsDataplane is used to select the dataplane used for Windows nodes. In particular, it
	// causes the operator to add required mounts and environment variables for the particular dataplane.
	// If not specified, it is disabled and the operator will not render the Calico Windows nodes daemonset.
	// Default: Disabled
	// +optional
	WindowsDataplane *WindowsDataplaneOption `json:"windowsDataplane,omitempty"`

	// BPFNetworkBootstrap manages the initial networking setup required to configure the BPF dataplane.
	//
	// When enabled, the operator tries to bootstraps access to the Kubernetes API Server
	// by using the Kubernetes service and its associated endpoints.
	//
	// This field should be enabled only if linuxDataplane is set to "BPF".
	// If another dataplane is selected, this field must be omitted or explicitly set to Disabled.
	//
	// When disabled and linuxDataplane is BPF, you must manually provide the Kubernetes API Server
	// information via the "kubernetes-service-endpoint" ConfigMap. It is invalid to use both the ConfigMap
	// and have this field set to true at the same time.
	// Default: Disabled
	// +optional
	// +kubebuilder:validation:Enum=Disabled;Enabled
	BPFNetworkBootstrap *BPFNetworkBootstrapType `json:"bpfNetworkBootstrap,omitempty"`

	// KubeProxyManagement controls whether the operator manages the kube-proxy DaemonSet.
	// When enabled, the operator will manage the DaemonSet by patching it:
	// it disables kube-proxy if the dataplane is BPF, or enables it otherwise.
	// Default: Disabled
	// +optional
	// +kubebuilder:validation:Enum=Disabled;Enabled
	KubeProxyManagement *KubeProxyManagementType `json:"kubeProxyManagement,omitempty"`

	// BGP configures whether or not to enable Calico's BGP capabilities.
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	BGP *BGPOption `json:"bgp,omitempty"`

	// ClusterRoutingMode controls how nodes get a route to a workload on another node,
	// when that workload's IP comes from an IP Pool with vxlanMode: Never. When ClusterRoutingMode is BIRD,
	// confd and BIRD program that route. When ClusterRoutingMode is Felix, it is expected that Felix will program that route.
	// Felix always programs such routes for IP Pools with vxlanMode: Always or vxlanMode: CrossSubnet. [Default: BIRD]
	// +optional
	ClusterRoutingMode *ClusterRoutingMode `json:"clusterRoutingMode,omitempty"`

	// IPPools contains a list of IP pools to manage. If nil, a single IPv4 IP pool
	// will be created by the operator. If an empty list is provided, the operator will not create any IP pools and will instead
	// wait for IP pools to be created out-of-band.
	// IP pools in this list will be reconciled by the operator and should not be modified out-of-band.
	// +optional
	// +kubebuilder:validation:MaxItems=25
	IPPools []IPPool `json:"ipPools,omitempty"`

	// MTU specifies the maximum transmission unit to use on the pod network.
	// If not specified, Calico will perform MTU auto-detection based on the cluster network.
	// +optional
	MTU *int32 `json:"mtu,omitempty"`

	// NodeAddressAutodetectionV4 specifies an approach to automatically detect node IPv4 addresses. If not specified,
	// will use default auto-detection settings to acquire an IPv4 address for each node.
	// +optional
	NodeAddressAutodetectionV4 *NodeAddressAutodetection `json:"nodeAddressAutodetectionV4,omitempty"`

	// NodeAddressAutodetectionV6 specifies an approach to automatically detect node IPv6 addresses. If not specified,
	// IPv6 addresses will not be auto-detected.
	// +optional
	NodeAddressAutodetectionV6 *NodeAddressAutodetection `json:"nodeAddressAutodetectionV6,omitempty"`

	// HostPorts configures whether or not Calico will support Kubernetes HostPorts. Valid only when using the Calico CNI plugin.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	HostPorts *HostPortsType `json:"hostPorts,omitempty"`

	// MultiInterfaceMode configures what will configure multiple interface per pod. Only valid for Calico Enterprise installations
	// using the Calico CNI plugin.
	// Default: None
	// +optional
	// +kubebuilder:validation:Enum=None;Multus
	MultiInterfaceMode *MultiInterfaceMode `json:"multiInterfaceMode,omitempty"`

	// ContainerIPForwarding configures whether ip forwarding will be enabled for containers in the CNI configuration.
	// Default: Disabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	ContainerIPForwarding *ContainerIPForwardingType `json:"containerIPForwarding,omitempty"`

	// LinuxPodInterfaceType selects the virtual device type the Calico CNI plugin
	// creates for each pod's interface on Linux nodes. When set to Netkit, the CNI
	// plugin creates a netkit L2 pair on kernels that support it (Linux 6.7+) and
	// falls back to a veth pair on older kernels. Netkit is recommended for the BPF
	// dataplane, where it allows BPF programs to attach via BPF_NETKIT_PRIMARY for
	// improved throughput and tail-latency under contention; for non-BPF dataplanes
	// it is functionally equivalent to veth. Only valid when using the Calico CNI
	// plugin.
	// Default: Veth
	// +optional
	LinuxPodInterfaceType *LinuxPodInterfaceType `json:"linuxPodInterfaceType,omitempty"`

	// Sysctl configures sysctl parameters for tuning plugin
	// +optional
	Sysctl []Sysctl `json:"sysctl,omitempty"`

	// LinuxPolicySetupTimeoutSeconds delays new pods from running containers
	// until their policy has been programmed in the dataplane.
	// The specified delay defines the maximum amount of time
	// that the Calico CNI plugin will wait for policy to be programmed.
	//
	// Only applies to pods created on Linux nodes.
	//
	// * A value of 0 disables pod startup delays.
	//
	// Default: 0
	// +optional
	LinuxPolicySetupTimeoutSeconds *int32 `json:"linuxPolicySetupTimeoutSeconds,omitempty"`
}

// NodeAddressAutodetection provides configuration options for auto-detecting node addresses. At most one option
// can be used. If no detection option is specified, then IP auto detection will be disabled for this address family and IPs
// must be specified directly on the Node resource.
//
// +kubebuilder:validation:XValidation:rule="[has(self.firstFound) && self.firstFound == true, has(self.kubernetes), has(self.interface) && size(self.interface) > 0, has(self.skipInterface) && size(self.skipInterface) > 0, has(self.canReach) && size(self.canReach) > 0, has(self.cidrs) && size(self.cidrs) > 0].filter(x, x).size() <= 1",message="no more than one autodetection method can be specified"
// +structType=atomic
type NodeAddressAutodetection struct {
	// FirstFound uses default interface matching parameters to select an interface, performing best-effort
	// filtering based on well-known interface names.
	// +optional
	FirstFound *bool `json:"firstFound,omitempty"`

	// Kubernetes configures Calico to detect node addresses based on the Kubernetes API.
	// +optional
	// +kubebuilder:validation:Enum=NodeInternalIP
	Kubernetes *KubernetesAutodetectionMethod `json:"kubernetes,omitempty"`

	// Interface enables IP auto-detection based on interfaces that match the given regex.
	// +optional
	Interface string `json:"interface,omitempty"`

	// SkipInterface enables IP auto-detection based on interfaces that do not match
	// the given regex.
	// +optional
	SkipInterface string `json:"skipInterface,omitempty"`

	// CanReach enables IP auto-detection based on which source address on the node is used to reach the
	// specified IP or domain.
	// +optional
	CanReach string `json:"canReach,omitempty"`

	// CIDRS enables IP auto-detection based on which addresses on the nodes are within
	// one of the provided CIDRs.
	CIDRS []string `json:"cidrs,omitempty"`
}

// KubernetesAutodetectionMethod is a method of detecting an IP address based on the Kubernetes API.
//
// One of: NodeInternalIP
type KubernetesAutodetectionMethod string

const (
	// NodeInternalIP detects a node IP using the first status.Addresses entry of the relevant IP family
	// with type NodeInternalIP on the Kubernetes nodes API.
	NodeInternalIP KubernetesAutodetectionMethod = "NodeInternalIP"
)

// EncapsulationType is the type of encapsulation to use on an IP pool.
//
// One of: IPIP, VXLAN, IPIPCrossSubnet, VXLANCrossSubnet, None
type EncapsulationType string

func (et EncapsulationType) String() string {
	return string(et)
}

const (
	EncapsulationIPIPCrossSubnet  EncapsulationType = "IPIPCrossSubnet"
	EncapsulationIPIP             EncapsulationType = "IPIP"
	EncapsulationVXLAN            EncapsulationType = "VXLAN"
	EncapsulationVXLANCrossSubnet EncapsulationType = "VXLANCrossSubnet"
	EncapsulationNone             EncapsulationType = "None"
)

var EncapsulationTypes []EncapsulationType = []EncapsulationType{
	EncapsulationIPIPCrossSubnet,
	EncapsulationIPIP,
	EncapsulationVXLAN,
	EncapsulationVXLANCrossSubnet,
	EncapsulationNone,
}

var EncapsulationTypesString []string = []string{
	EncapsulationIPIPCrossSubnet.String(),
	EncapsulationIPIP.String(),
	EncapsulationVXLAN.String(),
	EncapsulationVXLANCrossSubnet.String(),
	EncapsulationNone.String(),
}

// NATOutgoingType describe the type of outgoing NAT to use.
//
// One of: Enabled, Disabled
type NATOutgoingType string

const (
	NATOutgoingEnabled  NATOutgoingType = "Enabled"
	NATOutgoingDisabled NATOutgoingType = "Disabled"
)

var NATOutgoingTypes []NATOutgoingType = []NATOutgoingType{
	NATOutgoingEnabled,
	NATOutgoingDisabled,
}

var NATOutgoingTypesString []string = []string{
	NATOutgoingEnabled.String(),
	NATOutgoingDisabled.String(),
}

func (nt NATOutgoingType) String() string {
	return string(nt)
}

const NodeSelectorDefault string = "all()"

type AssignmentMode string

const (
	AssignmentModeAutomatic AssignmentMode = "Automatic"
	AssignmentModeManual    AssignmentMode = "Manual"
)

type IPPool struct {
	// Name is the name of the IP pool. If omitted, this will be generated.
	Name string `json:"name,omitempty"`

	// CIDR contains the address range for the IP Pool in classless inter-domain routing format.
	CIDR string `json:"cidr"`

	// Encapsulation specifies the encapsulation type that will be used with
	// the IP Pool.
	// Default: IPIP
	// +optional
	// +kubebuilder:validation:Enum=IPIPCrossSubnet;IPIP;VXLAN;VXLANCrossSubnet;None
	Encapsulation EncapsulationType `json:"encapsulation,omitempty"`

	// NATOutgoing specifies if NAT will be enabled or disabled for outgoing traffic.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	NATOutgoing NATOutgoingType `json:"natOutgoing,omitempty"`

	// NodeSelector specifies the node selector that will be set for the IP Pool.
	// Default: 'all()'
	// +optional
	NodeSelector string `json:"nodeSelector,omitempty"`

	// BlockSize specifies the CIDR prefex length to use when allocating per-node IP blocks from
	// the main IP pool CIDR.
	// Default: 26 (IPv4), 122 (IPv6)
	// +optional
	BlockSize *int32 `json:"blockSize,omitempty"`

	// DisableBGPExport specifies whether routes from this IP pool's CIDR are exported over BGP.
	// Default: false
	// +optional
	// +kubebuilder:default:=false
	DisableBGPExport *bool `json:"disableBGPExport,omitempty"`

	// DisableNewAllocations specifies whether or not new IP allocations are allowed from this pool.
	// This is useful when you want to prevent new pods from receiving IP addresses from this pool, without
	// impacting any existing pods that have already been assigned addresses from this pool.
	DisableNewAllocations *bool `json:"disableNewAllocations,omitempty"`

	// AllowedUse controls what the IP pool will be used for.  If not specified or empty, defaults to
	// ["Tunnel", "Workload"] for back-compatibility
	AllowedUses []IPPoolAllowedUse `json:"allowedUses,omitempty" validate:"omitempty"`

	// AssignmentMode determines if IP addresses from this pool should be  assigned automatically or on request only
	AssignmentMode AssignmentMode `json:"assignmentMode,omitempty" validate:"omitempty,assignmentMode"`
}

type IPPoolAllowedUse string

const (
	IPPoolAllowedUseWorkload     IPPoolAllowedUse = "Workload"
	IPPoolAllowedUseTunnel       IPPoolAllowedUse = "Tunnel"
	IPPoolAllowedUseLoadBalancer IPPoolAllowedUse = "LoadBalancer"
)

// CNIPluginType describes the type of CNI plugin used.
//
// One of: Calico, GKE, AmazonVPC, AzureVNET
type CNIPluginType string

const (
	PluginCalico    CNIPluginType = "Calico"
	PluginGKE       CNIPluginType = "GKE"
	PluginAmazonVPC CNIPluginType = "AmazonVPC"
	PluginAzureVNET CNIPluginType = "AzureVNET"
)

var CNIPluginTypes []CNIPluginType = []CNIPluginType{
	PluginCalico,
	PluginGKE,
	PluginAmazonVPC,
	PluginAzureVNET,
}

var CNIPluginTypesString []string = []string{
	PluginCalico.String(),
	PluginGKE.String(),
	PluginAmazonVPC.String(),
	PluginAzureVNET.String(),
}

func (cp CNIPluginType) String() string {
	return string(cp)
}

// CNISpecVersion is the version of the CNI specification declared in the
// CNI configuration generated by the operator.
type CNISpecVersion string

const (
	// CNISpecVersionAuto lets the operator choose the CNI spec version. The
	// chosen version may be raised in future operator versions as older
	// container runtimes fall out of support.
	CNISpecVersionAuto CNISpecVersion = "Auto"

	CNISpecVersion031 CNISpecVersion = "0.3.1"
	CNISpecVersion040 CNISpecVersion = "0.4.0"
	CNISpecVersion100 CNISpecVersion = "1.0.0"
)

// autoCNISpecVersion is the CNI spec version that Auto currently resolves
// to. All container runtimes supported by this operator accept it.
const autoCNISpecVersion = CNISpecVersion100

type IPAMPluginType string

const (
	IPAMPluginCalico    IPAMPluginType = "Calico"
	IPAMPluginHostLocal IPAMPluginType = "HostLocal"
	IPAMPluginAmazonVPC IPAMPluginType = "AmazonVPC"
	IPAMPluginAzureVNET IPAMPluginType = "AzureVNET"
)

var IPAMPluginTypes []IPAMPluginType = []IPAMPluginType{
	IPAMPluginCalico,
	IPAMPluginHostLocal,
	IPAMPluginAmazonVPC,
	IPAMPluginAzureVNET,
}

var IPAMPluginTypesString []string = []string{
	IPAMPluginCalico.String(),
	IPAMPluginHostLocal.String(),
	IPAMPluginAmazonVPC.String(),
	IPAMPluginAzureVNET.String(),
}

func (cp IPAMPluginType) String() string {
	return string(cp)
}

// IPAMSpec contains configuration for pod IP address management.
type IPAMSpec struct {
	// Specifies the IPAM plugin that will be used in the Calico or Calico Enterprise installation.
	// * For CNI Plugin Calico, this field defaults to Calico.
	// * For CNI Plugin GKE, this field defaults to HostLocal.
	// * For CNI Plugin AzureVNET, this field defaults to AzureVNET.
	// * For CNI Plugin AmazonVPC, this field defaults to AmazonVPC.
	//
	// The IPAM plugin is installed and configured only if the CNI plugin is set to Calico,
	// for all other values of the CNI plugin the plugin binaries and CNI config is a dependency
	// that is expected to be installed separately.
	//
	// Default: Calico
	// +kubebuilder:validation:Enum=Calico;HostLocal;AmazonVPC;AzureVNET
	Type IPAMPluginType `json:"type"`
}

// CNISpec contains configuration for the CNI plugin.
type CNISpec struct {
	// Specifies the CNI plugin that will be used in the Calico or Calico Enterprise installation.
	// * For KubernetesProvider GKE, this field defaults to GKE.
	// * For KubernetesProvider AKS, this field defaults to AzureVNET.
	// * For KubernetesProvider EKS, this field defaults to AmazonVPC.
	// * If aws-node daemonset exists in kube-system when the Installation resource is created, this field defaults to AmazonVPC.
	// * For all other cases this field defaults to Calico.
	//
	// For the value Calico, the CNI plugin binaries and CNI config will be installed as part of deployment,
	// for all other values the CNI plugin binaries and CNI config is a dependency that is expected
	// to be installed separately.
	//
	// Default: Calico
	// +kubebuilder:validation:Enum=Calico;GKE;AmazonVPC;AzureVNET
	Type CNIPluginType `json:"type"`

	// IPAM specifies the pod IP address management that will be used in the Calico or
	// Calico Enterprise installation.
	// +optional
	IPAM *IPAMSpec `json:"ipam"`

	// SpecVersion configures the CNI specification version declared in the
	// CNI configuration ("cniVersion") that the operator generates. Auto
	// (the default) lets the operator choose an appropriate version, which
	// may increase across operator upgrades. Pin an explicit version if a
	// chained CNI plugin or container runtime in your environment requires
	// one. Only relevant when using the Calico CNI plugin.
	// Default: Auto
	// +kubebuilder:validation:Enum=Auto;"0.3.1";"0.4.0";"1.0.0"
	// +optional
	SpecVersion *CNISpecVersion `json:"specVersion,omitempty"`

	// BinDir is the path to the CNI binaries directory.
	// If you have changed the installation directory for CNI binaries in the container runtime configuration,
	// please ensure that this field points to the same directory as specified in the container runtime settings.
	// Default directory depends on the KubernetesProvider.
	// * For KubernetesProvider GKE, this field defaults to "/home/kubernetes/bin".
	// * For KubernetesProvider OpenShift, this field defaults to "/var/lib/cni/bin".
	// * Otherwise, this field defaults to "/opt/cni/bin".
	// +optional
	// +kubebuilder:validation:Type=string
	BinDir *string `json:"binDir,omitempty"`

	// ConfDir is the path to the CNI config directory.
	// If you have changed the installation directory for CNI configuration in the container runtime configuration,
	// please ensure that this field points to the same directory as specified in the container runtime settings.
	// Default directory depends on the KubernetesProvider.
	// * For KubernetesProvider GKE, this field defaults to "/etc/cni/net.d".
	// * For KubernetesProvider OpenShift, this field defaults to "/var/run/multus/cni/net.d".
	// * Otherwise, this field defaults to "/etc/cni/net.d".
	// +optional
	// +kubebuilder:validation:Type=string
	ConfDir *string `json:"confDir,omitempty"`

	// InstallMode controls which CNI plugin binaries the operator installs onto each node
	// when CNI.Type is Calico.
	// * All (default): the operator runs a cni-plugins init container that stages upstream
	//   CNI plugin binaries (host-local, portmap, loopback, tuning, flannel) into a shared
	//   volume, and the install-cni init container copies them onto the host alongside
	//   Calico's own binaries.
	// * CalicoOnly: skip the cni-plugins init container. Only Calico's own binaries are
	//   installed. Use this when the host already provides the upstream plugins (e.g. kind,
	//   certain managed node images).
	//
	// Default: All
	// +optional
	// +kubebuilder:validation:Enum=All;CalicoOnly
	InstallMode *CNIInstallMode `json:"installMode,omitempty"`
}

// CNIInstallMode controls which CNI plugin binaries the operator installs onto the host.
type CNIInstallMode string

const (
	// CNIInstallModeAll installs Calico's own CNI binaries plus the upstream plugin set
	// (host-local, portmap, loopback, tuning, flannel) via a dedicated init container.
	CNIInstallModeAll CNIInstallMode = "All"

	// CNIInstallModeCalicoOnly installs only Calico's own CNI binaries; the host is
	// expected to provide any required upstream plugins.
	CNIInstallModeCalicoOnly CNIInstallMode = "CalicoOnly"
)

// InstallationStatus defines the observed state of the Calico or Calico Enterprise installation.
type InstallationStatus struct {
	// Variant is the most recently observed installed variant - one of Calico or CalicoEnterprise.
	// TigeraSecureEnterprise is a deprecated alias for CalicoEnterprise.
	// +kubebuilder:validation:Enum=Calico;CalicoEnterprise;TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`

	// MTU is the most recently observed value for pod network MTU. This may be an explicitly
	// configured value, or based on Calico's native auto-detetion.
	MTU int32 `json:"mtu,omitempty"`

	// ImageSet is the name of the ImageSet being used, if there is an ImageSet
	// that is being used. If an ImageSet is not being used then this will not be set.
	// +optional
	ImageSet string `json:"imageSet,omitempty"`

	// Computed is the final installation including overlaid resources.
	// +optional
	Computed *InstallationSpec `json:"computed,omitempty"`

	// CalicoVersion shows the current running version of calico.
	// CalicoVersion along with Variant is needed to know the exact
	// version deployed.
	CalicoVersion string `json:"calicoVersion,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ResolvedSpecVersion is an extension method that returns the CNI spec
// version to declare in the generated CNI config ("cniVersion"), resolving
// Auto (and unset) to the operator's current default.
func (c *CNISpec) ResolvedSpecVersion() string {
	if c == nil || c.SpecVersion == nil || *c.SpecVersion == CNISpecVersionAuto {
		return string(autoCNISpecVersion)
	}
	return string(*c.SpecVersion)
}

// BPFEnabled is an extension method that returns true if the Installation resource
// has Calico Network Linux Dataplane set and equal to value "BPF" otherwise false.
func (s *InstallationSpec) BPFEnabled() bool {
	return s.CalicoNetwork != nil &&
		s.CalicoNetwork.LinuxDataplane != nil &&
		*s.CalicoNetwork.LinuxDataplane == LinuxDataplaneBPF
}

// IsNftables is an extension method that returns true if the Installation resource
// has Calico Network Linux Dataplane set and equal to value "Nftables" or "BPF", otherwise false.
//
// BPF is included here as it uses nftables to program some rules, except when on DockerEE,
// since docker-ee programs some rules in iptables. These rules does not interact well with the
// nftable rules that calico programs, so we exclude BPF when on DockerEE.
func (s *InstallationSpec) IsNftables() bool {
	if s.CalicoNetwork != nil && s.CalicoNetwork.LinuxDataplane != nil {
		if s.KubernetesProvider.IsDockerEE() &&
			(*s.CalicoNetwork.LinuxDataplane == LinuxDataplaneBPF) {
			return false
		}
		return (*s.CalicoNetwork.LinuxDataplane == LinuxDataplaneNftables ||
			*s.CalicoNetwork.LinuxDataplane == LinuxDataplaneBPF)
	}
	return false
}

func (installation *InstallationSpec) BPFNetworkBootstrapEnabled() bool {
	return installation != nil &&
		installation.CalicoNetwork != nil &&
		installation.CalicoNetwork.BPFNetworkBootstrap != nil &&
		*installation.CalicoNetwork.BPFNetworkBootstrap == BPFNetworkBootstrapEnabled
}

func (installation *InstallationSpec) KubeProxyManagementEnabled() bool {
	return installation != nil &&
		installation.CalicoNetwork != nil &&
		installation.CalicoNetwork.KubeProxyManagement != nil &&
		*installation.CalicoNetwork.KubeProxyManagement == KubeProxyManagementEnabled
}

// +kubebuilder:object:root=true

// InstallationList contains a list of Installation
type InstallationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Installation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Installation{}, &InstallationList{})
}

// CertificateManagement configures pods to submit a CertificateSigningRequest to the certificates.k8s.io/v1beta1 API in order
// to obtain TLS certificates. This feature requires that you bring your own CSR signing and approval process, otherwise
// pods will be stuck during initialization.
type CertificateManagement struct {
	// Certificate of the authority that signs the CertificateSigningRequests in PEM format.
	CACert []byte `json:"caCert"`

	// When a CSR is issued to the certificates.k8s.io API, the signerName is added to the request in order to accommodate for clusters
	// with multiple signers.
	// Must be formatted as: `<my-domain>/<my-signername>`.
	SignerName string `json:"signerName"`

	// Specify the algorithm used by pods to generate a key pair that is associated with the X.509 certificate request.
	// Default: RSAWithSize2048
	// +kubebuilder:validation:Enum="";RSAWithSize2048;RSAWithSize4096;RSAWithSize8192;ECDSAWithCurve256;ECDSAWithCurve384;ECDSAWithCurve521;
	// +optional
	KeyAlgorithm string `json:"keyAlgorithm,omitempty"`

	// Specify the algorithm used for the signature of the X.509 certificate request.
	// Default: SHA256WithRSA
	// +kubebuilder:validation:Enum="";SHA256WithRSA;SHA384WithRSA;SHA512WithRSA;ECDSAWithSHA256;ECDSAWithSHA384;ECDSAWithSHA512;
	// +optional
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
}

// IsFIPSModeEnabled is a convenience function for turning a FIPSMode reference into a bool.
func IsFIPSModeEnabled(mode *FIPSMode) bool {
	return mode != nil && *mode == FIPSModeEnabled
}

type WindowsNodeSpec struct {
	// CNIBinDir is the path to the CNI binaries directory on Windows, it must match what is used as 'bin_dir' under
	// [plugins]
	//   [plugins."io.containerd.grpc.v1.cri"]
	//     [plugins."io.containerd.grpc.v1.cri".cni]
	// on the containerd 'config.toml' file on the Windows nodes.
	// +optional
	CNIBinDir string `json:"cniBinDir,omitempty"`

	// CNIConfigDir is the path to the CNI configuration directory on Windows, it must match what is used as 'conf_dir' under
	// [plugins]
	//   [plugins."io.containerd.grpc.v1.cri"]
	//     [plugins."io.containerd.grpc.v1.cri".cni]
	// on the containerd 'config.toml' file on the Windows nodes.
	// +optional
	CNIConfigDir string `json:"cniConfigDir,omitempty"`

	// CNILogDir is the path to the Calico CNI logs directory on Windows.
	// +optional
	CNILogDir string `json:"cniLogDir,omitempty"`

	// VXLANMACPrefix is the prefix used when generating MAC addresses for virtual NICs
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}$`
	VXLANMACPrefix string `json:"vxlanMACPrefix,omitempty"`

	// VXLANAdapter is the Network Adapter used for VXLAN, leave blank for primary NIC
	// +optional
	VXLANAdapter string `json:"vxlanAdapter,omitempty"`
}

type Proxy struct {
	// HTTPProxy defines the value of the HTTP_PROXY environment variable that will be set on Tigera containers that connect to
	// destinations outside the cluster.
	// +optional
	HTTPProxy string `json:"httpProxy,omitempty"`

	// HTTPSProxy defines the value of the HTTPS_PROXY environment variable that will be set on Tigera containers that connect to
	// destinations outside the cluster.
	// +optional
	HTTPSProxy string `json:"httpsProxy,omitempty"`

	// NoProxy defines the value of the NO_PROXY environment variable that will be set on Tigera containers that connect to
	// destinations outside the cluster. This value must be set such that destinations within the scope of the cluster, including
	// the Kubernetes API server, are exempt from being proxied.
	// +optional
	NoProxy string `json:"noProxy,omitempty"`
}

func (p *Proxy) EnvVars() (envVars []v1.EnvVar) {
	if p == nil {
		return
	}

	if p.HTTPProxy != "" {
		envVars = append(envVars, []v1.EnvVar{
			{
				Name:  "HTTP_PROXY",
				Value: p.HTTPProxy,
			},
			{
				Name:  "http_proxy",
				Value: p.HTTPProxy,
			},
		}...)
	}

	if p.HTTPSProxy != "" {
		envVars = append(envVars, []v1.EnvVar{
			{
				Name:  "HTTPS_PROXY",
				Value: p.HTTPSProxy,
			},
			{
				Name:  "https_proxy",
				Value: p.HTTPSProxy,
			},
		}...)
	}

	if p.NoProxy != "" {
		envVars = append(envVars, []v1.EnvVar{
			{
				Name:  "NO_PROXY",
				Value: p.NoProxy,
			},
			{
				Name:  "no_proxy",
				Value: p.NoProxy,
			},
		}...)
	}

	return envVars
}
