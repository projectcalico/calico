// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package types

import "github.com/projectcalico/calico/felix/rules"

type Reporter interface {
	Start() error
	Report(interface{}) error
}

type TrafficDirection int

const (
	TrafficDirInbound TrafficDirection = iota
	TrafficDirOutbound
)

const (
	TrafficDirInboundStr  = "inbound"
	TrafficDirOutboundStr = "outbound"
)

func (t TrafficDirection) String() string {
	if t == TrafficDirInbound {
		return TrafficDirInboundStr
	}
	return TrafficDirOutboundStr
}

// RuleDirToTrafficDir converts the rule direction to the equivalent traffic direction
// (useful for NFLOG based updates where ingress/inbound and egress/outbound are tied).
func RuleDirToTrafficDir(r rules.RuleDir) TrafficDirection {
	if r == rules.RuleDirIngress {
		return TrafficDirInbound
	}
	return TrafficDirOutbound
}
