// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
//
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

package hns

import (
	"encoding/json"
	"net"
)

// This file contains stub/mock versions of the hcsshim API, which compile on Linux.  When ading new
// shims to hns_windows.go, add stubbed versions of the types and structs here so that the HNS code can
// be compiled and tested on Windows. Since we can't import hcsshim here we have to make reasonable
// type substitutes.  For upstream types that are typedeffed strings, simply repeat the typedef here.
// For upstream types that are structs, create a compatible type definition including at least the
// fields we use.

// Types from hnssupport.go.

type HNSSupportedFeatures struct {
	Acl HNSAclFeatures
}

type HNSAclFeatures struct {
	AclAddressLists       bool
	AclNoHostRulePriority bool
	AclPortRanges         bool
	AclRuleId             bool
}

// Types from hnspolicy.go.

// Type of Request Support in ModifySystem
type PolicyType string

// RequestType const
const (
	Nat                  PolicyType = "NAT"
	ACL                  PolicyType = "ACL"
	PA                   PolicyType = "PA"
	VLAN                 PolicyType = "VLAN"
	VSID                 PolicyType = "VSID"
	VNet                 PolicyType = "VNET"
	L2Driver             PolicyType = "L2Driver"
	Isolation            PolicyType = "Isolation"
	QOS                  PolicyType = "QOS"
	OutboundNat          PolicyType = "OutBoundNAT"
	ExternalLoadBalancer PolicyType = "ELB"
	Route                PolicyType = "ROUTE"
	Proxy                PolicyType = "PROXY"
)

// Not currently used on Linux...
//
//type NatPolicy = hcsshim.NatPolicy
//
//type QosPolicy = hcsshim.QosPolicy
//
//type IsolationPolicy = hcsshim.IsolationPolicy
//
//type VlanPolicy = hcsshim.VlanPolicy
//
//type VsidPolicy = hcsshim.VsidPolicy
//
//type PaPolicy = hcsshim.PaPolicy
//
//type OutboundNatPolicy = hcsshim.OutboundNatPolicy
//
//type ProxyPolicy = hcsshim.ProxyPolicy

type ActionType string
type DirectionType string
type RuleType string

const (
	Allow ActionType = "Allow"
	Block ActionType = "Block"

	In  DirectionType = "In"
	Out DirectionType = "Out"

	Host   RuleType = "Host"
	Switch RuleType = "Switch"
)

type ACLPolicy struct {
	Type            PolicyType
	Id              string
	Protocol        uint16
	Protocols       string
	InternalPort    uint16
	Action          ActionType
	Direction       DirectionType
	LocalAddresses  string
	RemoteAddresses string
	LocalPorts      string
	LocalPort       uint16
	RemotePorts     string
	RemotePort      uint16
	RuleType        RuleType
	Priority        uint16
	ServiceName     string
}

type Policy struct {
	Type PolicyType `json:"Type"`
}

// Types from hnsendpoint.go.

// EndpointState represents the states of an HNS Endpoint lifecycle.
type EndpointState uint16

const (
	Uninitialized   EndpointState = iota
	Created         EndpointState = 1
	Attached        EndpointState = 2
	AttachedSharing EndpointState = 3
	Detached        EndpointState = 4
	Degraded        EndpointState = 5
	Destroyed       EndpointState = 6
)

// EndpointState const
// The lifecycle of an Endpoint goes through created, attached, AttachedSharing - endpoint is being shared with other containers,
// detached, after being attached, degraded and finally destroyed.
func (es EndpointState) String() string {
	return [...]string{"Uninitialized", "Attached", "AttachedSharing", "Detached", "Degraded", "Destroyed"}[es]
}

// HNSEndpoint represents a network endpoint in HNS
type HNSEndpoint struct {
	Id                 string            `json:"ID,omitempty"`
	Name               string            `json:",omitempty"`
	VirtualNetwork     string            `json:",omitempty"`
	VirtualNetworkName string            `json:",omitempty"`
	Policies           []json.RawMessage `json:",omitempty"`
	MacAddress         string            `json:",omitempty"`
	IPAddress          net.IP            `json:",omitempty"`
	IPv6Address        net.IP            `json:",omitempty"`
	DNSSuffix          string            `json:",omitempty"`
	DNSServerList      string            `json:",omitempty"`
	DNSDomain          string            `json:",omitempty"`
	GatewayAddress     string            `json:",omitempty"`
	GatewayAddressV6   string            `json:",omitempty"`
	EnableInternalDNS  bool              `json:",omitempty"`
	DisableICC         bool              `json:",omitempty"`
	PrefixLength       uint8             `json:",omitempty"`
	IPv6PrefixLength   uint8             `json:",omitempty"`
	IsRemoteEndpoint   bool              `json:",omitempty"`
	EnableLowMetric    bool              `json:",omitempty"`
	//Namespace          *Namespace        `json:",omitempty"`
	EncapOverhead    uint16        `json:",omitempty"`
	SharedContainers []string      `json:",omitempty"`
	State            EndpointState `json:",omitempty"`
}

// ApplyACLPolicy applies a set of ACL Policies on the Endpoint
func (endpoint *HNSEndpoint) ApplyACLPolicy(policies ...*ACLPolicy) error {
	return nil
}

type API struct{}

func (a API) GetHNSSupportedFeatures() HNSSupportedFeatures {
	return HNSSupportedFeatures{}
}

func (a API) HNSListEndpointRequest() ([]HNSEndpoint, error) {
	return nil, nil
}
