// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	KindCalicoNodeStatus     = "CalicoNodeStatus"
	KindCalicoNodeStatusList = "CalicoNodeStatusList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster

// CalicoNodeStatusList is a list of CalicoNodeStatus resources.
type CalicoNodeStatusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Items []CalicoNodeStatus `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster

type CalicoNodeStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Spec CalicoNodeStatusSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`

	//+optional
	Status CalicoNodeStatusStatus `json:"status" protobuf:"bytes,2,opt,name=status"`
}

// CalicoNodeStatusSpec contains the specification for a CalicoNodeStatus resource.
type CalicoNodeStatusSpec struct {
	// The node name identifies the Calico node instance for node status.
	Node string `json:"node,omitempty" validate:"required,name"`

	// Classes declares the types of information to monitor for this calico/node,
	// and allows for selective status reporting about certain subsets of information.
	Classes []NodeStatusClassType `json:"classes,omitempty" validate:"required,unique"`

	// UpdatePeriodSeconds is the period at which CalicoNodeStatus should be updated.
	// Set to 0 to disable CalicoNodeStatus refresh. Maximum update period is one day.
	UpdatePeriodSeconds *uint32 `json:"updatePeriodSeconds,omitempty" validate:"required,gte=0,lte=86400"`
}

// CalicoNodeStatusStatus defines the observed state of CalicoNodeStatus.
// No validation needed for status since it is updated by Calico.
type CalicoNodeStatusStatus struct {
	// LastUpdated is a timestamp representing the server time when CalicoNodeStatus object
	// last updated. It is represented in RFC3339 form and is in UTC.
	// +nullable
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated"`

	// Agent holds agent status on the node.
	// +optional
	Agent CalicoNodeAgentStatus `json:"agent"`

	// BGP holds node BGP status.
	// +optional
	BGP CalicoNodeBGPStatus `json:"bgp"`

	// Routes reports routes known to the Calico BGP daemon on the node.
	// +optional
	Routes CalicoNodeBGPRouteStatus `json:"routes"`
}

// CalicoNodeAgentStatus defines the observed state of agent status on the node.
type CalicoNodeAgentStatus struct {
	// BIRDV4 represents the latest observed status of bird4.
	// +optional
	BIRDV4 BGPDaemonStatus `json:"birdV4"`

	// BIRDV6 represents the latest observed status of bird6.
	// +optional
	BIRDV6 BGPDaemonStatus `json:"birdV6"`
}

// CalicoNodeBGPStatus defines the observed state of BGP status on the node.
type CalicoNodeBGPStatus struct {
	// The total number of IPv4 established bgp sessions.
	NumberEstablishedV4 int `json:"numberEstablishedV4"`

	// The total number of IPv4 non-established bgp sessions.
	NumberNotEstablishedV4 int `json:"numberNotEstablishedV4"`

	// The total number of IPv6 established bgp sessions.
	NumberEstablishedV6 int `json:"numberEstablishedV6"`

	// The total number of IPv6 non-established bgp sessions.
	NumberNotEstablishedV6 int `json:"numberNotEstablishedV6"`

	// PeersV4 represents IPv4 BGP peers status on the node.
	PeersV4 []CalicoNodePeer `json:"peersV4,omitempty"`

	// PeersV6 represents IPv6 BGP peers status on the node.
	PeersV6 []CalicoNodePeer `json:"peersV6,omitempty"`
}

// CalicoNodeBGPRouteStatus defines the observed state of routes status on the node.
type CalicoNodeBGPRouteStatus struct {
	// RoutesV4 represents IPv4 routes on the node.
	RoutesV4 []CalicoNodeRoute `json:"routesV4,omitempty"`

	// RoutesV6 represents IPv6 routes on the node.
	RoutesV6 []CalicoNodeRoute `json:"routesV6,omitempty"`
}

// BGPDaemonStatus defines the observed state of BGP daemon.
type BGPDaemonStatus struct {
	// The state of the BGP Daemon.
	State BGPDaemonState `json:"state,omitempty"`

	// Version of the BGP daemon
	Version string `json:"version,omitempty"`

	// Router ID used by bird.
	RouterID string `json:"routerID,omitempty"`

	// LastBootTime holds the value of lastBootTime from bird.ctl output.
	LastBootTime string `json:"lastBootTime,omitempty"`

	// LastReconfigurationTime holds the value of lastReconfigTime from bird.ctl output.
	LastReconfigurationTime string `json:"lastReconfigurationTime,omitempty"`
}

// CalicoNodePeer contains the status of BGP peers on the node.
type CalicoNodePeer struct {
	// IP address of the peer whose condition we are reporting.
	PeerIP string `json:"peerIP,omitempty" validate:"omitempty,ip"`

	// Type indicates whether this peer is configured via the node-to-node mesh,
	// or via en explicit global or per-node BGPPeer object.
	Type BGPPeerType `json:"type,omitempty"`

	// State is the BGP session state.
	State BGPSessionState `json:"state,omitempty"`

	// Since the state or reason last changed.
	Since string `json:"since,omitempty"`
}

// CalicoNodeRoute contains the status of BGP routes on the node.
type CalicoNodeRoute struct {
	// Type indicates if the route is being used for forwarding or not.
	Type CalicoNodeRouteType `json:"type,omitempty"`

	// Destination of the route.
	Destination string `json:"destination,omitempty"`

	// Gateway for the destination.
	Gateway string `json:"gateway,omitempty"`

	// Interface for the destination
	Interface string `json:"interface,omitempty"`

	// LearnedFrom contains information regarding where this route originated.
	LearnedFrom CalicoNodeRouteLearnedFrom `json:"learnedFrom,omitempty"`
}

// CalicoNodeRouteLearnedFrom contains the information of the source from which a routes has been learned.
type CalicoNodeRouteLearnedFrom struct {
	// Type of the source where a route is learned from.
	SourceType CalicoNodeRouteSourceType `json:"sourceType,omitempty"`

	// If sourceType is NodeMesh or BGPPeer, IP address of the router that sent us this route.
	PeerIP string `json:"peerIP,omitempty" validate:"omitempty,ip"`
}

// NewCalicoNodeStatus creates a new (zeroed) CalicoNodeStatus struct with the TypeMetadata initialised to the current
// version.
func NewCalicoNodeStatus() *CalicoNodeStatus {
	return &CalicoNodeStatus{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindCalicoNodeStatus,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// +kubebuilder:validation:Enum=FIB;RIB
type CalicoNodeRouteType string

const (
	RouteTypeFIB CalicoNodeRouteType = "FIB"
	RouteTypeRIB CalicoNodeRouteType = "RIB"
)

// +kubebuilder:validation:Enum=Kernel;Static;Direct;NodeMesh;BGPPeer
type CalicoNodeRouteSourceType string

const (
	RouteSourceTypeKernel   CalicoNodeRouteSourceType = "Kernel"
	RouteSourceTypeStatic   CalicoNodeRouteSourceType = "Static"
	RouteSourceTypeDirect   CalicoNodeRouteSourceType = "Direct"
	RouteSourceTypeNodeMesh CalicoNodeRouteSourceType = "NodeMesh"
	RouteSourceTypeBGPPeer  CalicoNodeRouteSourceType = "BGPPeer"
)

// +kubebuilder:validation:Enum=Agent;BGP;Routes
type NodeStatusClassType string

const (
	NodeStatusClassTypeAgent  NodeStatusClassType = "Agent"
	NodeStatusClassTypeBGP    NodeStatusClassType = "BGP"
	NodeStatusClassTypeRoutes NodeStatusClassType = "Routes"
)

// +kubebuilder:validation:Enum=NodeMesh;NodePeer;GlobalPeer
type BGPPeerType string

const (
	BGPPeerTypeNodeMesh   BGPPeerType = "NodeMesh"
	BGPPeerTypeNodePeer   BGPPeerType = "NodePeer"
	BGPPeerTypeGlobalPeer BGPPeerType = "GlobalPeer"
)

// +kubebuilder:validation:Enum=Ready;NotReady
type BGPDaemonState string

const (
	BGPDaemonStateReady    BGPDaemonState = "Ready"
	BGPDaemonStateNotReady BGPDaemonState = "NotReady"
)

// +kubebuilder:validation:Enum=Idle;Connect;Active;OpenSent;OpenConfirm;Established;Close
type BGPSessionState string

const (
	BGPSessionStateIdle        BGPSessionState = "Idle"
	BGPSessionStateConnect     BGPSessionState = "Connect"
	BGPSessionStateActive      BGPSessionState = "Active"
	BGPSessionStateOpenSent    BGPSessionState = "OpenSent"
	BGPSessionStateOpenConfirm BGPSessionState = "OpenConfirm"
	BGPSessionStateEstablished BGPSessionState = "Established"
	BGPSessionStateClose       BGPSessionState = "Close"
)
