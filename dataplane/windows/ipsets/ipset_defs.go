//+build windows

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"github.com/projectcalico/libcalico-go/lib/set"
)

// IPSetMetadata contains the metadata for a particular IP set, such as its name and type.
type IPSetMetadata struct {
	SetID string
	Type  IPSetType
}

// IPSetsDataplane is interface for managing a plane of ipSet objects.
type IPSetsDataplane interface {
	AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveIPSet(setID string)
}

// IPSetType constants for the different kinds of IP set.
type IPSetType string

const (
	IPSetTypeHashIP  IPSetType = "hash:ip"
	IPSetTypeHashNet IPSetType = "hash:net"
)

func (t IPSetType) SetType() string {
	return string(t)
}

func (t IPSetType) IsValid() bool {
	switch t {
	case IPSetTypeHashIP, IPSetTypeHashNet:
		return true
	}
	return false
}

// IPFamily constants to represent the IP family being managed by this IPSet
type IPFamily string

const (
	IPFamilyV4 = IPFamily("inet")
	IPFamilyV6 = IPFamily("inet6")
)

func (f IPFamily) IsValid() bool {
	switch f {
	case IPFamilyV4, IPFamilyV6:
		return true
	}
	return false
}

// ipSet holds the state for a particular IP set.
type ipSet struct {
	IPSetMetadata
	Members set.Set
}

// IPVersionConfig wraps up the metadata for a particular IP version.
type IPVersionConfig struct {
	Family IPFamily
}

func NewIPVersionConfig(family IPFamily) *IPVersionConfig {
	return &IPVersionConfig{
		Family: family,
	}
}
