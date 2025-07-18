// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindQoSPolicy     = "QoSPolicy"
	KindQoSPolicyList = "QoSPolicyList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// QoSPolicyList is a list of QoSPolicy resources.
type QoSPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []QoSPolicy `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type QoSPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec QoSPolicySpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// QoSPolicySpec contains the specification of QoS policies.
type QoSPolicySpec struct {
	// Order is an optional field that specifies the order in which the policy is applied.
	// Policies with higher "order" are applied after those with lower
	// order within the same tier. If the order is omitted, it may be considered to be "infinite" - i.e. the
	// policy will be applied last. Policies with identical order will be applied in
	// alphanumerical order based on the Policy "Name".
	Order *float64 `json:"order,omitempty"`

	// The selector is an expression used to pick out the endpoints that the policy should
	// be applied to.
	Selector string `json:"selector,omitempty" validate:"selector"`

	// NamespaceSelector is an optional field for an expression used to select a pod based on namespaces.
	NamespaceSelector string `json:"namespaceSelector,omitempty" validate:"selector"`

	// The set of QoS Policies
	Egress []QoSRule `json:"egress,omitempty" validate:"required"`
}

// QoSRule defines a QoS rule
type QoSRule struct {
	Action QoSAction `json:"action" validate:"qosAction"`

	// IPVersion is an optional field that restricts the rule to only match a specific IP
	// version.
	IPVersion *int `json:"ipVersion,omitempty" validate:"omitempty,ipVersion"`

	// Protocol is an optional field that restricts the rule to only apply to traffic of
	// a specific IP protocol. Required if any of the EntityRules contain Ports
	// (because ports only apply to certain protocols).
	//
	// Must be one of these string values: "TCP", "UDP", "ICMP", "ICMPv6", "SCTP", "UDPLite"
	// or an integer in the range 1-255.
	Protocol *numorstring.Protocol `json:"protocol,omitempty" validate:"omitempty"`

	// Destination contains the match criteria that apply to destination entity.
	Destination QoSEntityRule `json:"destination,omitempty" validate:"omitempty"`
}

// A QoSEntityRule is a sub-component of a Rule comprising the match criteria specific
// to a particular entity (that is destination).
//
// A destination QoSEntityRule matches the destination endpoint and terminating traffic.
type QoSEntityRule struct {
	// Nets is an optional field that restricts the rule to only apply to traffic that
	// terminates at IP addresses in any of the given subnets.
	Nets []string `json:"nets,omitempty" validate:"omitempty,dive,net"`

	// Ports is an optional field that restricts the rule to only apply to traffic that has a
	// destination port that matches one of these ranges/values. This value is a
	// list of integers or strings that represent ranges of ports.
	//
	// Since only some protocols have ports, if any ports are specified it requires the
	// Protocol match in the Rule to be set to "TCP" or "UDP".
	Ports []numorstring.Port `json:"ports,omitempty" validate:"omitempty,dive"`
}

type QoSAction struct {
	// DSCP is an optional field that states what DSCP value must be set on the selected traffic.
	// The value can be either an integer between 0 and 63 (inclusive) or one of the following string values:
	// "DF", "EF", "AF11", "AF12", "AF13", "AF21", "AF22", "AF23", "AF31", "AF32", "AF33", "AF41", "AF42", "AF43",
	// "CS0", "CS1", "CS2", "CS3", "CS4", "CS5", "CS6".
	DSCP *numorstring.DSCP `json:"dscp,omitempty" validate:"omitempty"`
}

// New QoSPolicy creates a new (zeroed) QoSPolicy struct with the TypeMetadata
// initialized to the current version.
func NewQoSPolicy() *QoSPolicy {
	return &QoSPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindQoSPolicy,
			APIVersion: GroupVersionCurrent,
		},
	}
}
