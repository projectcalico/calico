// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package apiv2

import (
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

// PolicySpec contains the specification for a selector-based security Policy resource.
type PolicySpec struct {
	// Order is an optional field that specifies the order in which the policy is applied.
	// Policies with higher "order" are applied after those with lower
	// order.  If the order is omitted, it may be considered to be "infinite" - i.e. the
	// policy will be applied last.  Policies with identical order will be applied in
	// alphanumerical order based on the Policy "Name".
	Order *float64 `json:"order,omitempty"`
	// The ordered set of ingress rules.  Each rule contains a set of packet match criteria and
	// a corresponding action to apply.
	IngressRules []Rule `json:"ingress,omitempty" validate:"omitempty,dive"`
	// The ordered set of egress rules.  Each rule contains a set of packet match criteria and
	// a corresponding action to apply.
	EgressRules []Rule `json:"egress,omitempty" validate:"omitempty,dive"`
	// The selector is an expression used to pick pick out the endpoints that the policy should
	// be applied to.
	//
	// Selector expressions follow this syntax:
	//
	// 	label == "string_literal"  ->  comparison, e.g. my_label == "foo bar"
	// 	label != "string_literal"   ->  not equal; also matches if label is not present
	// 	label in { "a", "b", "c", ... }  ->  true if the value of label X is one of "a", "b", "c"
	// 	label not in { "a", "b", "c", ... }  ->  true if the value of label X is not one of "a", "b", "c"
	// 	has(label_name)  -> True if that label is present
	// 	! expr -> negation of expr
	// 	expr && expr  -> Short-circuit and
	// 	expr || expr  -> Short-circuit or
	// 	( expr ) -> parens for grouping
	// 	all() or the empty selector -> matches all endpoints.
	//
	// Label names are allowed to contain alphanumerics, -, _ and /. String literals are more permissive
	// but they do not support escape characters.
	//
	// Examples (with made-up labels):
	//
	// 	type == "webserver" && deployment == "prod"
	// 	type in {"frontend", "backend"}
	// 	deployment != "dev"
	// 	! has(label_name)
	Selector string `json:"selector" validate:"selector"`
	// DoNotTrack indicates whether packets matched by the rules in this policy should go through
	// the data plane's connection tracking, such as Linux conntrack.  If True, the rules in
	// this policy are applied before any data plane connection tracking, and packets allowed by
	// this policy are marked as not to be tracked.
	DoNotTrack bool `json:"doNotTrack,omitempty"`
	// PreDNAT indicates to apply the rules in this policy before any DNAT.
	PreDNAT bool `json:"preDNAT,omitempty"`
	// Types indicates whether this policy applies to ingress, or to egress, or to both.  When
	// not explicitly specified (and so the value on creation is empty or nil), Calico defaults
	// Types according to what IngressRules and EgressRules are present in the policy.  The
	// default is:
	//
	// - [ PolicyTypeIngress ], if there are no EgressRules (including the case where there are
	//   also no IngressRules)
	//
	// - [ PolicyTypeEgress ], if there are EgressRules but no IngressRules
	//
	// - [ PolicyTypeIngress, PolicyTypeEgress ], if there are both IngressRules and EgressRules.
	//
	// When the policy is read back again, Types will always be one of these values, never empty
	// or nil.
	Types []PolicyType `json:"types,omitempty" validate:"omitempty,dive,policytype"`
}

// PolicyType enumerates the possible values of the PolicySpec Types field.
type PolicyType string

const (
	PolicyTypeIngress PolicyType = "Ingress"
	PolicyTypeEgress  PolicyType = "Egress"
)

// A Rule encapsulates a set of match criteria and an action.  Both selector-based security Policy
// and security Profiles reference rules - separated out as a list of rules for both
// ingress and egress packet matching.
//
// Each positive match criteria has a negated version, prefixed with ”Not”. All the match
// criteria within a rule must be satisfied for a packet to match. A single rule can contain
// the positive and negative version of a match and both must be satisfied for the rule to match.
type Rule struct {
	Action Action `json:"action" validate:"action"`
	// IPVersion is an optional field that restricts the rule to only match a specific IP
	// version.
	IPVersion *int `json:"ipVersion,omitempty" validate:"omitempty,ipversion"`
	// Protocol is an optional field that restricts the rule to only apply to traffic of
	// a specific IP protocol. Required if any of the EntityRules contain Ports
	// (because ports only apply to certain protocols).
	//
	// Must be one of these string values: "tcp", "udp", "icmp", "icmpv6", "sctp", "udplite"
	// or an integer in the range 1-255.
	Protocol *numorstring.Protocol `json:"protocol,omitempty" validate:"omitempty"`
	// ICMP is an optional field that restricts the rule to apply to a specific type and
	// code of ICMP traffic.  This should only be specified if the Protocol field is set to
	// "icmp" or "icmpv6".
	ICMP *ICMPFields `json:"icmp,omitempty" validate:"omitempty"`
	// NotProtocol is the negated version of the Protocol field.
	NotProtocol *numorstring.Protocol `json:"notProtocol,omitempty" validate:"omitempty"`
	// NotICMP is the negated version of the ICMP field.
	NotICMP *ICMPFields `json:"notICMP,omitempty" validate:"omitempty"`
	// Source contains the match criteria that apply to source entity.
	Source EntityRule `json:"source,omitempty" validate:"omitempty"`
	// Destination contains the match criteria that apply to destination entity.
	Destination EntityRule `json:"destination,omitempty" validate:"omitempty"`
}

// ICMPFields defines structure for ICMP and NotICMP sub-struct for ICMP code and type
type ICMPFields struct {
	// Match on a specific ICMP type.  For example a value of 8 refers to ICMP Echo Request
	// (i.e. pings).
	Type *int `json:"type,omitempty" validate:"omitempty,gte=0,lte=254"`
	// Match on a specific ICMP code.  If specified, the Type value must also be specified.
	// This is a technical limitation imposed by the kernel’s iptables firewall, which
	// Calico uses to enforce the rule.
	Code *int `json:"code,omitempty" validate:"omitempty,gte=0,lte=255"`
}

// An EntityRule is a sub-component of a Rule comprising the match criteria specific
// to a particular entity (that is either the source or destination).
//
// A source EntityRule matches the source endpoint and originating traffic.
// A destination EntityRule matches the destination endpoint and terminating traffic.
type EntityRule struct {
	// Tag is an optional field that restricts the rule to only apply to traffic that
	// originates from (or terminates at) endpoints that have profiles with the given tag
	// in them.
	Tag string `json:"tag,omitempty" validate:"omitempty,tag"`
	// Nets is an optional field that restricts the rule to only apply to traffic that
	// originates from (or terminates at) IP addresses in any of the given subnets.
	Nets []string `json:"nets,omitempty" validate:"omitempty,dive,cidr"`
	// Selector is an optional field that contains a selector expression (see Policy for
	// sample syntax).  Only traffic that originates from (terminates at) endpoints matching
	// the selector will be matched.
	//
	// Note that: in addition to the negated version of the Selector (see NotSelector below), the
	// selector expression syntax itself supports negation.  The two types of negation are subtly
	// different. One negates the set of matched endpoints, the other negates the whole match:
	//
	//	Selector = "!has(my_label)" matches packets that are from other Calico-controlled
	// 	endpoints that do not have the label “my_label”.
	//
	// 	NotSelector = "has(my_label)" matches packets that are not from Calico-controlled
	// 	endpoints that do have the label “my_label”.
	//
	// The effect is that the latter will accept packets from non-Calico sources whereas the
	// former is limited to packets from Calico-controlled endpoints.
	Selector string `json:"selector,omitempty" validate:"omitempty,selector"`
	// Ports is an optional field that restricts the rule to only apply to traffic that has a
	// source (destination) port that matches one of these ranges/values. This value is a
	// list of integers or strings that represent ranges of ports.
	//
	// Since only some protocols have ports, if any ports are specified it requires the
	// Protocol match in the Rule to be set to "tcp" or "udp".
	Ports []numorstring.Port `json:"ports,omitempty" validate:"omitempty,dive"`
	// NotTag is the negated version of the Tag field.
	NotTag string `json:"notTag,omitempty" validate:"omitempty,tag"`
	// NotNets is an optional field that restricts the rule to only apply to traffic that
	// does not originate from (or terminate at) an IP address in any of the given subnets.
	NotNets []string `json:"notNets,omitempty" validate:"omitempty,dive,cidr"`
	// NotSelector is the negated version of the Selector field.  See Selector field for
	// subtleties with negated selectors.
	NotSelector string `json:"notSelector,omitempty" validate:"omitempty,selector"`
	// NotPorts is the negated version of the Ports field.
	// Since only some protocols have ports, if any ports are specified it requires the
	// Protocol match in the Rule to be set to "tcp" or "udp".
	NotPorts []numorstring.Port `json:"notPorts,omitempty" validate:"omitempty,dive"`
}

type Action string

const (
	Allow Action = "Allow"
	Deny         = "Deny"
	Log          = "Log"
	Pass         = "Pass"
)
