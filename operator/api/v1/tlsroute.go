// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type TargetType string

const (
	TargetTypeUpstreamTunnel TargetType = "UpstreamTunnel"
	TargetTypeUI             TargetType = "UI"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced

type TLSTerminatedRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TLSTerminatedRouteSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSTerminatedRouteList contains a list of ManagedCluster resources.
type TLSTerminatedRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TLSTerminatedRoute `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TLSPassThroughRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Dest is the destination URL
	Spec TLSPassThroughRouteSpec `json:"spec"`
}

type TLSPassThroughRouteSpec struct {
	// +kubebuilder:validation:Enum=UpstreamTunnel
	// +required
	Target TargetType `json:"target"`

	// SNIMatch is used to match requests based on the server name for the intended destination server. Matching requests
	// will be proxied to the Destination.
	// +required
	SNIMatch *SNIMatch `json:"sniMatch"`

	// Destination is the destination url to proxy the request to.
	// +required
	Destination string `json:"destination"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TLSPassThroughRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TLSPassThroughRoute `json:"items"`
}

type TLSTerminatedRouteSpec struct {
	// +kubebuilder:validation:Enum=UpstreamTunnel;UI
	Target TargetType `json:"target"`

	// PathMatch is used to match requests based on what's in the path. Matching requests will be proxied to the Destination
	// defined in this structure.
	// +required
	PathMatch *PathMatch `json:"pathMatch"`

	// Destination is the destination URL where matching traffic is routed to.
	// +required
	Destination string `json:"destination"`

	// CABundle is where we read the CA bundle from to authenticate the
	// destination (if non-empty)
	// +required
	CABundle *v1.ConfigMapKeySelector `json:"caBundle,omitempty"`

	// ForwardingMTLSCert is the certificate used for mTLS between voltron and the destination. Either both ForwardingMTLSCert
	// and ForwardingMTLSKey must be specified, or neither can be specified.
	// +optional
	ForwardingMTLSCert *v1.SecretKeySelector `json:"mtlsCert,omitempty"`

	// ForwardingMTLSKey is the key used for mTLS between voltron and the destination. Either both ForwardingMTLSCert
	// and ForwardingMTLSKey must be specified, or neither can be specified.
	// +optional
	ForwardingMTLSKey *v1.SecretKeySelector `json:"mtlsKey,omitempty"`

	// Unauthenticated says whether the request should go through authentication. This is only applicable if the Target
	// is UI.
	// +optional
	Unauthenticated *bool `json:"unauthenticated"`
}

type PathMatch struct {
	// Path is the path portion of the URL based on which we proxy.
	// +required
	Path string `json:"path"`

	// PathRegexp, if not nil, checks if Regexp matches the path.
	// +optional
	PathRegexp *string `json:"pathRegexp,omitempty"`

	// PathReplace if not nil will be used to replace PathRegexp matches.
	// +optional
	PathReplace *string `json:"pathReplace,omitempty"`
}

type SNIMatch struct {
	// ServerName is used to match the server name for the request.
	ServerName string `json:"serverName"`
}

func init() {
	SchemeBuilder.Register(&TLSTerminatedRoute{}, &TLSTerminatedRouteList{}, &TLSPassThroughRoute{}, &TLSPassThroughRouteList{})
}
