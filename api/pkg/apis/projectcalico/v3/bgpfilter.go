// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

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
	KindBGPFilter     = "BGPFilter"
	KindBGPFilterList = "BGPFilterList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPFilterList is a list of BGPFilter resources.
type BGPFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Items []BGPFilter `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
type BGPFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

	Spec BGPFilterSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`
}

// BGPFilterSpec contains the IPv4 and IPv6 filter rules of the BGP Filter.
type BGPFilterSpec struct {
	// The ordered set of IPv4 BGPFilter rules acting on exporting routes to a peer.
	ExportV4 []BGPFilterRuleV4 `json:"exportV4,omitempty" validate:"omitempty,dive"`

	// The ordered set of IPv4 BGPFilter rules acting on importing routes from a peer.
	// Source is not applicable to import rules because all imported routes are from BGP peers by definition.
	// +kubebuilder:validation:XValidation:rule="self.all(r, !has(r.source) || r.source == '')",message="source is not applicable to import rules"
	ImportV4 []BGPFilterRuleV4 `json:"importV4,omitempty" validate:"omitempty,dive"`

	// The ordered set of IPv6 BGPFilter rules acting on exporting routes to a peer.
	ExportV6 []BGPFilterRuleV6 `json:"exportV6,omitempty" validate:"omitempty,dive"`

	// The ordered set of IPv6 BGPFilter rules acting on importing routes from a peer.
	// Source is not applicable to import rules because all imported routes are from BGP peers by definition.
	// +kubebuilder:validation:XValidation:rule="self.all(r, !has(r.source) || r.source == '')",message="source is not applicable to import rules"
	ImportV6 []BGPFilterRuleV6 `json:"importV6,omitempty" validate:"omitempty,dive"`
}

// BGPFilterRuleV4 defines a BGP filter rule consisting of match criteria, a terminal action,
// and optional operations to apply to matching routes.
// +mapType=atomic
// +kubebuilder:validation:XValidation:rule="(has(self.cidr) && size(self.cidr) > 0) == (has(self.matchOperator) && size(self.matchOperator) > 0)",message="cidr and matchOperator must both be set or both be empty",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="!has(self.prefixLength) || (has(self.cidr) && size(self.cidr) > 0)",message="cidr is required when prefixLength is set",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="!has(self.operations) || size(self.operations) == 0 || self.action == 'Accept'",message="operations may only be used with action Accept"
type BGPFilterRuleV4 struct {
	// If non-empty, this filter rule will only apply when the route being exported or imported
	// "matches" the given CIDR - where the definition of "matches" is according to
	// MatchOperator and PrefixLength.  CIDR should be in conventional CIDR notation,
	// <prefix>/<length>.
	// +kubebuilder:validation:Format=cidr
	// +kubebuilder:validation:MaxLength=18
	CIDR string `json:"cidr,omitempty" validate:"omitempty,netv4"`

	// PrefixLength further constrains the CIDR match by restricting the range of allowed
	// prefix lengths.  For example, CIDR "10.0.0.0/8" with MatchOperator "In" and
	// PrefixLength {min: 16, max: 24} matches any route within 10.0.0.0/8 whose prefix
	// length is between /16 and /24.  Only meaningful when CIDR is also specified; if
	// PrefixLength is nil, the CIDR's own prefix length is used as the minimum and /32
	// (for V4) as the maximum.
	// +optional
	PrefixLength *BGPFilterPrefixLengthV4 `json:"prefixLength,omitempty" validate:"omitempty"`

	// If set to "RemotePeers": for export rules, this filter rule will only apply to routes
	// learned from BGP peers (i.e. re-advertised routes), not locally originated routes.
	// For import rules, this field is redundant because imported routes are by definition
	// from BGP peers.
	Source BGPFilterMatchSource `json:"source,omitempty" validate:"omitempty,oneof=RemotePeers"`

	// If non-empty, this filter rule will only apply to routes with an outgoing interface that
	// matches Interface.
	Interface string `json:"interface,omitempty" validate:"omitempty,bgpFilterInterface"`

	// MatchOperator defines how the route's prefix is compared against CIDR.  "Equal" requires
	// an exact prefix match, "In" requires the route to be contained within the CIDR (or equal),
	// "NotEqual" and "NotIn" are their negations.  Only meaningful when CIDR is also specified.
	// Required when CIDR is set.
	MatchOperator BGPFilterMatchOperator `json:"matchOperator,omitempty" validate:"omitempty,matchOperator"`

	// If non-empty, this filter rule will only apply to routes being imported from or exported
	// to a BGP peer of the specified type.  If empty, the rule applies to all peers.
	// +optional
	PeerType BGPFilterPeerType `json:"peerType,omitempty" validate:"omitempty,oneof=eBGP iBGP"`

	// If set, this filter rule will only apply to routes that carry the specified BGP
	// community.  On import, this matches communities set by the remote peer.  On export,
	// this matches communities already present on the route, whether received from a BGP
	// peer (e.g. on a route reflector re-advertising to an eBGP peer) or added locally
	// by an import filter or an earlier export rule's AddCommunity operation.
	// +optional
	Communities *BGPFilterCommunityMatch `json:"communities,omitempty" validate:"omitempty"`

	// If non-empty, this filter rule will only apply to routes whose AS path begins with the
	// specified sequence of AS numbers.
	// +optional
	ASPathPrefix []numorstring.ASNumber `json:"asPathPrefix,omitempty" validate:"omitempty,dive"`

	// If set, this filter rule will only apply to routes with the given priority, in the
	// same units as the ...RoutePriority fields in FelixConfiguration.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483646
	Priority *int `json:"priority,omitempty" validate:"omitempty,gte=1,lte=2147483646"`

	Action BGPFilterAction `json:"action" validate:"required,filterAction"`

	// Operations is an ordered list of route modifications to apply to matching routes before
	// accepting them.  Only valid when Action is "Accept"; specifying operations with "Reject"
	// is rejected by validation.  Each entry must set exactly one operation field.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Operations []BGPFilterOperation `json:"operations,omitempty" validate:"omitempty,dive"`
}

// BGPFilterRuleV6 defines a BGP filter rule consisting of match criteria, a terminal action,
// and optional operations to apply to matching routes.
// +mapType=atomic
// +kubebuilder:validation:XValidation:rule="(has(self.cidr) && size(self.cidr) > 0) == (has(self.matchOperator) && size(self.matchOperator) > 0)",message="cidr and matchOperator must both be set or both be empty",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="!has(self.prefixLength) || (has(self.cidr) && size(self.cidr) > 0)",message="cidr is required when prefixLength is set",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="!has(self.operations) || size(self.operations) == 0 || self.action == 'Accept'",message="operations may only be used with action Accept"
type BGPFilterRuleV6 struct {
	// If non-empty, this filter rule will only apply when the route being exported or imported
	// "matches" the given CIDR - where the definition of "matches" is according to
	// MatchOperator and PrefixLength.  CIDR should be in conventional CIDR notation,
	// <prefix>/<length>.
	// +kubebuilder:validation:Format=cidr
	// +kubebuilder:validation:MaxLength=43
	CIDR string `json:"cidr,omitempty" validate:"omitempty,netv6"`

	// PrefixLength further constrains the CIDR match by restricting the range of allowed
	// prefix lengths.  For example, CIDR "fd00::/8" with MatchOperator "In" and
	// PrefixLength {min: 48, max: 64} matches any route within fd00::/8 whose prefix
	// length is between /48 and /64.  Only meaningful when CIDR is also specified; if
	// PrefixLength is nil, the CIDR's own prefix length is used as the minimum and /128
	// (for V6) as the maximum.
	// +optional
	PrefixLength *BGPFilterPrefixLengthV6 `json:"prefixLength,omitempty" validate:"omitempty"`

	// If set to "RemotePeers": for export rules, this filter rule will only apply to routes
	// learned from BGP peers (i.e. re-advertised routes), not locally originated routes.
	// For import rules, this field is redundant because imported routes are by definition
	// from BGP peers.
	Source BGPFilterMatchSource `json:"source,omitempty" validate:"omitempty,oneof=RemotePeers"`

	// If non-empty, this filter rule will only apply to routes with an outgoing interface that
	// matches Interface.
	Interface string `json:"interface,omitempty" validate:"omitempty,bgpFilterInterface"`

	// MatchOperator defines how the route's prefix is compared against CIDR.  "Equal" requires
	// an exact prefix match, "In" requires the route to be contained within the CIDR (or equal),
	// "NotEqual" and "NotIn" are their negations.  Only meaningful when CIDR is also specified.
	// Required when CIDR is set.
	MatchOperator BGPFilterMatchOperator `json:"matchOperator,omitempty" validate:"omitempty,matchOperator"`

	// If non-empty, this filter rule will only apply to routes being imported from or exported
	// to a BGP peer of the specified type.  If empty, the rule applies to all peers.
	// +optional
	PeerType BGPFilterPeerType `json:"peerType,omitempty" validate:"omitempty,oneof=eBGP iBGP"`

	// If set, this filter rule will only apply to routes that carry the specified BGP
	// community.  On import, this matches communities set by the remote peer.  On export,
	// this matches communities already present on the route, whether received from a BGP
	// peer (e.g. on a route reflector re-advertising to an eBGP peer) or added locally
	// by an import filter or an earlier export rule's AddCommunity operation.
	// +optional
	Communities *BGPFilterCommunityMatch `json:"communities,omitempty" validate:"omitempty"`

	// If non-empty, this filter rule will only apply to routes whose AS path begins with the
	// specified sequence of AS numbers.
	// +optional
	ASPathPrefix []numorstring.ASNumber `json:"asPathPrefix,omitempty" validate:"omitempty,dive"`

	// If set, this filter rule will only apply to routes with the given priority, in the
	// same units as the ...RoutePriority fields in FelixConfiguration.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483646
	Priority *int `json:"priority,omitempty" validate:"omitempty,gte=1,lte=2147483646"`

	Action BGPFilterAction `json:"action" validate:"required,filterAction"`

	// Operations is an ordered list of route modifications to apply to matching routes before
	// accepting them.  Only valid when Action is "Accept"; specifying operations with "Reject"
	// is rejected by validation.  Each entry must set exactly one operation field.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Operations []BGPFilterOperation `json:"operations,omitempty" validate:"omitempty,dive"`
}

// +mapType=atomic
type BGPFilterPrefixLengthV4 struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32
	Min *int32 `json:"min,omitempty" validate:"omitempty,bgpFilterPrefixLengthV4"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32
	Max *int32 `json:"max,omitempty" validate:"omitempty,bgpFilterPrefixLengthV4"`
}

// +mapType=atomic
type BGPFilterPrefixLengthV6 struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	Min *int32 `json:"min,omitempty" validate:"omitempty,bgpFilterPrefixLengthV6"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	Max *int32 `json:"max,omitempty" validate:"omitempty,bgpFilterPrefixLengthV6"`
}

// +kubebuilder:validation:Enum=RemotePeers
type BGPFilterMatchSource string

const (
	BGPFilterSourceRemotePeers BGPFilterMatchSource = "RemotePeers"
)

// +kubebuilder:validation:Enum=Equal;NotEqual;In;NotIn
type BGPFilterMatchOperator string

const (
	MatchOperatorEqual    BGPFilterMatchOperator = "Equal"
	MatchOperatorNotEqual BGPFilterMatchOperator = "NotEqual"
	MatchOperatorIn       BGPFilterMatchOperator = "In"
	MatchOperatorNotIn    BGPFilterMatchOperator = "NotIn"
)

// +kubebuilder:validation:Enum=Accept;Reject
type BGPFilterAction string

const (
	Accept BGPFilterAction = "Accept"
	Reject BGPFilterAction = "Reject"
)

// BGPFilterPeerType specifies which type of BGP peer a filter rule applies to.
// +kubebuilder:validation:Enum=eBGP;iBGP
type BGPFilterPeerType string

const (
	BGPFilterPeerTypeEBGP BGPFilterPeerType = "eBGP"
	BGPFilterPeerTypeIBGP BGPFilterPeerType = "iBGP"
)

// BGPCommunityValue is a BGP community string in `aa:nn` (standard) or `aa:nn:mm` (large) format.
// For standard communities, each component must be a 16-bit value (0-65535).
// For large communities, each component must be a 32-bit value (0-4294967295).
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^(([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[0-1][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[0-1][0-9]{2}|42949672[0-8][0-9]|429496729[0-5]):([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[0-1][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[0-1][0-9]{2}|42949672[0-8][0-9]|429496729[0-5]):([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[0-1][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[0-1][0-9]{2}|42949672[0-8][0-9]|429496729[0-5]))$`
type BGPCommunityValue string

// BGPFilterCommunityMatch specifies community-based match criteria for a BGP filter rule.
// Currently only a single community value is supported.  A MatchOperator field may be
// introduced in the future to support anyOf/allOf semantics with multiple values.
// +mapType=atomic
type BGPFilterCommunityMatch struct {
	// Values is a list of BGP community values to match against.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	Values []BGPCommunityValue `json:"values" validate:"required,dive"`
}

// BGPFilterOperation is a discriminated union representing a single route modification.
// Exactly one field must be set.
// +mapType=atomic
// +kubebuilder:validation:XValidation:rule="(has(self.addCommunity) ? 1 : 0) + (has(self.prependASPath) ? 1 : 0) + (has(self.setPriority) ? 1 : 0) == 1",message="exactly one operation must be set"
type BGPFilterOperation struct {
	// AddCommunity adds the specified BGP community to the route.
	// +optional
	AddCommunity *BGPFilterAddCommunity `json:"addCommunity,omitempty" validate:"omitempty"`

	// PrependASPath prepends the specified AS numbers to the route's AS path.
	// +optional
	PrependASPath *BGPFilterPrependASPath `json:"prependASPath,omitempty" validate:"omitempty"`

	// SetPriority sets the route's priority (metric), in the same units as the
	// ...RoutePriority fields in FelixConfiguration.
	// +optional
	SetPriority *BGPFilterSetPriority `json:"setPriority,omitempty" validate:"omitempty"`
}

// BGPFilterAddCommunity specifies a BGP community to add to a route.
// +mapType=atomic
type BGPFilterAddCommunity struct {
	// Value is the BGP community to add.
	Value BGPCommunityValue `json:"value" validate:"required"`
}

// BGPFilterPrependASPath specifies AS numbers to prepend to a route's AS path.
// +mapType=atomic
type BGPFilterPrependASPath struct {
	// Prefix is the sequence of AS numbers to prepend to the route's AS path.
	// The resulting path starts with these AS numbers in the order listed;
	// e.g. [65000, 65001] produces the path "65000 65001 <original>".
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Prefix []numorstring.ASNumber `json:"prefix" validate:"required,dive"`
}

// BGPFilterSetPriority specifies a route priority to set.
// +mapType=atomic
type BGPFilterSetPriority struct {
	// Value is the priority to set, in the same units as FelixConfiguration's
	// ...RoutePriority fields.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483646
	Value int `json:"value" validate:"required,gte=1,lte=2147483646"`
}

// New BGPFilter creates a new (zeroed) BGPFilter struct with the TypeMetadata
// initialized to the current version.
func NewBGPFilter() *BGPFilter {
	return &BGPFilter{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBGPFilter,
			APIVersion: GroupVersionCurrent,
		},
	}
}
