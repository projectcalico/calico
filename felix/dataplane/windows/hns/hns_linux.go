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
// For upstream types that are structs, create a compatible type definiiton including at least the
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
	Nat                  PolicyType = "Nat"
	ACL                  PolicyType = "ACL"
	PA                   PolicyType = "PA"
	VLAN                 PolicyType = "VLAN"
	VSID                 PolicyType = "VSID"
	VNet                 PolicyType = "VNet"
	L2Driver             PolicyType = "L2Driver"
	Isolation            PolicyType = "Isolation"
	QOS                  PolicyType = "QOS"
	OutboundNat          PolicyType = "OutboundNat"
	ExternalLoadBalancer PolicyType = "ExternalLoadBalancer"
	Route                PolicyType = "Route"
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
}

// Types from hnsendpoint.go.

// HNSEndpoint represents a network endpoint in HNS
type HNSEndpoint struct {
	Id                 string
	Name               string
	VirtualNetwork     string
	VirtualNetworkName string
	Policies           []json.RawMessage
	MacAddress         string
	IPAddress          net.IP
	DNSSuffix          string
	DNSServerList      string
	GatewayAddress     string
	EnableInternalDNS  bool
	DisableICC         bool
	PrefixLength       uint8
	IsRemoteEndpoint   bool
	// Namespace          *Namespace
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

func (_ API) GetAttachedContainerIDs(endpoint *HNSEndpoint) ([]string, error) {
	return nil, nil
}
