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

// This package is a shim for the hcsshim API.  Packages in Felix should import this package instead
// of importing hcsshim directly.  This file is only compiled on Windows and it should use the
// real hcsshim API.
package hns

import "github.com/Microsoft/hcsshim"

// Adding to the file
//
// To shim a type from the hcsshim package, use a type alias, which re-exports the real type:
//
//     type HNSSupportedFeatures = hcsshim.HNSSupportedFeatures
//
// note the "=", which causes the exported type to be the exact same type as the one from hcsshim.
//
// To shim a function, define a wrapper method on the API struct. Using a struct allows for easier
// mocking in UT.
//
// Remember to add equivalent mock function to hns_linux.go.

// Types from hnssupport.go.

type HNSSupportedFeatures = hcsshim.HNSSupportedFeatures

// Types from hnspolicy.go.

// Type of Request Support in ModifySystem
type PolicyType = hcsshim.PolicyType

// RequestType const
const (
	Nat                  = hcsshim.Nat
	ACL                  = hcsshim.ACL
	PA                   = hcsshim.PA
	VLAN                 = hcsshim.VLAN
	VSID                 = hcsshim.VSID
	VNet                 = hcsshim.VNet
	L2Driver             = hcsshim.L2Driver
	Isolation            = hcsshim.Isolation
	QOS                  = hcsshim.QOS
	OutboundNat          = hcsshim.OutboundNat
	ExternalLoadBalancer = hcsshim.ExternalLoadBalancer
	Route                = hcsshim.Route
)

type NatPolicy = hcsshim.NatPolicy

type QosPolicy = hcsshim.QosPolicy

type IsolationPolicy = hcsshim.IsolationPolicy

type VlanPolicy = hcsshim.VlanPolicy

type VsidPolicy = hcsshim.VsidPolicy

type PaPolicy = hcsshim.PaPolicy

type OutboundNatPolicy = hcsshim.OutboundNatPolicy

type ActionType = hcsshim.ActionType
type DirectionType = hcsshim.DirectionType
type RuleType = hcsshim.RuleType

const (
	Allow = hcsshim.Allow
	Block = hcsshim.Block

	In  = hcsshim.In
	Out = hcsshim.Out

	Host   = hcsshim.Host
	Switch = hcsshim.Switch
)

type ACLPolicy = hcsshim.ACLPolicy

type Policy = hcsshim.Policy

// Types from hnsendpoint.go.

type HNSEndpoint = hcsshim.HNSEndpoint

// API is our shim for the hcsshim.<Name> functions.
type API struct{}

func (_ API) GetHNSSupportedFeatures() HNSSupportedFeatures {
	return hcsshim.GetHNSSupportedFeatures()
}

func (_ API) HNSListEndpointRequest() ([]HNSEndpoint, error) {
	return hcsshim.HNSListEndpointRequest()
}

func (_ API) GetAttachedContainerIDs(endpoint *HNSEndpoint) ([]string, error) {
	return endpoint.GetAttachedContainerIDs()
}
