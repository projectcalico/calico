// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.

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

package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindIPPool     = "IPPool"
	KindIPPoolList = "IPPoolList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster,shortName={ipp,ipps,pool,pools}

// IPPoolList contains a list of IPPool resources.
type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Items []IPPool `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="CIDR",type=string,JSONPath=".spec.cidr",description="The pool CIDR"
// +kubebuilder:printcolumn:name="VXLAN",type=string,JSONPath=".spec.vxlanMode",description="The VXLAN mode for this pool"
// +kubebuilder:printcolumn:name="IPIP",type=string,JSONPath=".spec.ipipMode",description="The IPIP mode for this pool"
// +kubebuilder:printcolumn:name="NAT",type=boolean,JSONPath=".spec.natOutgoing",description="Whether outgoing NAT is enabled for this pool"
// +kubebuilder:printcolumn:name="Allocatable",type="string",JSONPath=".status.conditions[?(@.type=='Allocatable')].status",description="Whether or not this pool is available for IP allocations"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp",description="The age of the pool"

type IPPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Spec IPPoolSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`

	// +optional
	Status *IPPoolStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

const (
	// IPPoolConditionReady indicates whether the pool is ready to be used for IP address assignment.
	IPPoolConditionAllocatable = "Allocatable"
)

const (
	// IPPoolReasonCIDRInvalid indicates that the pool CIDR overlaps with another IP pool.
	IPPoolReasonCIDROverlap = "CIDROverlap"

	// IPPoolReasonTerminating indicates that the pool is terminating and cannot be used for new IP address assignments.
	IPPoolReasonTerminating = "Terminating"

	// IPPoolReasonDisabled indicates the pool is administratively disabled and cannot be used for new IP address assignments.
	IPPoolReasonDisabled = "PoolDisabled"

	// IPPoolReasonOK indicates that the pool is ready to be used for IP address assignment.
	IPPoolReasonOK = "OK"
)

type IPPoolStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty" protobuf:"bytes,1,rep,name=conditions"`
}

// IPPoolSpec contains the specification for an IPPool resource.
type IPPoolSpec struct {
	// The pool CIDR.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	CIDR string `json:"cidr" validate:"net"`

	// Contains configuration for VXLAN tunneling for this pool.
	VXLANMode VXLANMode `json:"vxlanMode,omitempty" validate:"omitempty,vxlanMode"`

	// Contains configuration for IPIP tunneling for this pool.
	// For IPv6 pools, IPIP tunneling must be disabled.
	IPIPMode IPIPMode `json:"ipipMode,omitempty" validate:"omitempty,ipIpMode"`

	// When natOutgoing is true, packets sent from Calico networked containers in
	// this pool to destinations outside of this pool will be masqueraded.
	NATOutgoing bool `json:"natOutgoing,omitempty"`

	// When disabled is true, Calico IPAM will not assign addresses from this pool.
	Disabled bool `json:"disabled,omitempty"`

	// Disable exporting routes from this IP Pool's CIDR over BGP. [Default: false]
	DisableBGPExport bool `json:"disableBGPExport,omitempty" validate:"omitempty"`

	// The block size to use for IP address assignments from this pool. Defaults to 26 for IPv4 and 122 for IPv6.
	// The block size must be between 0 and 32 for IPv4 and between 0 and 128 for IPv6. It must also be smaller than
	// or equal to the size of the pool CIDR.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	BlockSize int `json:"blockSize,omitempty"`

	// Allows IPPool to allocate for a specific node by label selector.
	NodeSelector string `json:"nodeSelector,omitempty" validate:"omitempty,selector"`

	// Allows IPPool to allocate for a specific namespace by label selector.
	// If specified, both namespaceSelector and nodeSelector must match for the pool to be used.
	NamespaceSelector string `json:"namespaceSelector,omitempty" validate:"omitempty,selector"`

	// AllowedUse controls what the IP pool will be used for.  If not specified or empty, defaults to
	// ["Tunnel", "Workload"] for back-compatibility
	// +listType=set
	AllowedUses []IPPoolAllowedUse `json:"allowedUses,omitempty" validate:"omitempty"`

	// Determines the mode how IP addresses should be assigned from this pool
	// +optional
	// +kubebuilder:default=Automatic
	AssignmentMode *AssignmentMode `json:"assignmentMode,omitempty" validate:"omitempty,assignmentMode"`
}

// IPPoolAllowedUse defines the allowed uses for an IP pool.
// It can be one of "Workload", "Tunnel", or "LoadBalancer".
// - "Workload" means the pool is used for workload IP addresses.
// - "Tunnel" means the pool is used for tunnel IP addresses.
// - "LoadBalancer" means the pool is used for load balancer IP addresses.
// +kubebuilder:validation:Enum=Workload;Tunnel;LoadBalancer
type IPPoolAllowedUse string

const (
	IPPoolAllowedUseWorkload IPPoolAllowedUse = "Workload"
	IPPoolAllowedUseTunnel   IPPoolAllowedUse = "Tunnel"

	// IPPoolAllowedUseLoadBalancer designates that the pool is used for load balancer IP addresses.
	// Not compatible with IPIP or VXLAN.
	IPPoolAllowedUseLoadBalancer IPPoolAllowedUse = "LoadBalancer"
)

// VXLANMode defines the mode of VXLAN tunneling for an IP pool.
// It can be one of "Never", "Always", or "CrossSubnet".
// - "Never" means VXLAN tunneling is disabled for this pool.
// - "Always" means VXLAN tunneling is used for all traffic to this pool.
// - "CrossSubnet" means VXLAN tunneling is used only when the destination node is on a different subnet.
// +kubebuilder:validation:Enum=Never;Always;CrossSubnet
type VXLANMode string

const (
	VXLANModeNever       VXLANMode = "Never"
	VXLANModeAlways      VXLANMode = "Always"
	VXLANModeCrossSubnet VXLANMode = "CrossSubnet"
)

// IPIPMode defines the mode of IPIP tunneling for an IP pool.
// It can be one of "Never", "Always", or "CrossSubnet".
// - "Never" means IPIP tunneling is disabled for this pool.
// - "Always" means IPIP tunneling is used for all traffic to this pool.
// - "CrossSubnet" means IPIP tunneling is used only when the destination node is on a different subnet.
// +kubebuilder:validation:Enum=Never;Always;CrossSubnet
type IPIPMode string

const (
	IPIPModeNever       IPIPMode = "Never"
	IPIPModeAlways      IPIPMode = "Always"
	IPIPModeCrossSubnet IPIPMode = "CrossSubnet"
)

// The following definitions are only used for APIv1 backwards compatibility.
// They are for internal use only.
type EncapMode string

const (
	Never       EncapMode = ""
	Always      EncapMode = "always"
	CrossSubnet EncapMode = "cross-subnet"
)

// +kubebuilder:validation:Enum=Automatic;Manual
type AssignmentMode string

const (
	Automatic AssignmentMode = "Automatic"
	Manual    AssignmentMode = "Manual"
)

const DefaultMode = Always

type IPIPConfiguration struct {
	// When enabled is true, ipip tunneling will be used to deliver packets to
	// destinations within this pool.
	Enabled bool `json:"enabled,omitempty"`

	// The IPIP mode.  This can be one of "always" or "cross-subnet".  A mode
	// of "always" will also use IPIP tunneling for routing to destination IP
	// addresses within this pool.  A mode of "cross-subnet" will only use IPIP
	// tunneling when the destination node is on a different subnet to the
	// originating node.  The default value (if not specified) is "always".
	Mode EncapMode `json:"mode,omitempty" validate:"ipIpMode"`
}

// NewIPPool creates a new (zeroed) IPPool struct with the TypeMetadata initialised to the current
// version.
func NewIPPool() *IPPool {
	return &IPPool{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindIPPool,
			APIVersion: GroupVersionCurrent,
		},
	}
}
