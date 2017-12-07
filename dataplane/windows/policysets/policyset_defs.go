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

package policysets

import (
	"errors"

	hns "github.com/Microsoft/hcsshim"

	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	// the ip family of this policy set, currently set to V4.
	// V6 will be added once dataplane support is available.
	ipVersion uint8 = 4
	// default dataplane rule priority for any rules generated
	// from a Policy set.
	rulePriority uint16 = 1000
	// prefix to use for all policy names
	PolicyNamePrefix string = "policy-"
	// prefix to use for all profile names
	ProfileNamePrefix string = "profile-"
)

var (
	SkipRule   = errors.New("Rule skipped")
	MissingSet = errors.New("Missing IPSet")
)

// PolicySetType constants for the different kinds of Policy set.
type PolicySetType string

const (
	PolicySetTypePolicy  PolicySetType = "policy"
	PolicySetTypeProfile PolicySetType = "profile"
)

func (t PolicySetType) SetType() string {
	return string(t)
}

// PolicySetMetadata contains the metadata for a particular Policy set, such as its name and type.
type PolicySetMetadata struct {
	SetId string
	Type  PolicySetType
}

// PolicySetsDataplane is a interface for managing a plane of policySet objects
type PolicySetsDataplane interface {
	AddOrReplacePolicySet(setId string, policy interface{})
	RemovePolicySet(setId string)
	NewRule(isInbound bool, priority uint16) *hns.ACLPolicy
	GetPolicySetRules(setIds []string) (rules []*hns.ACLPolicy)
	ProcessIpSetUpdate(ipSetId string) []string
}

// policySet holds the state for a particular Policy set.
type policySet struct {
	// metadata for the Policy set.
	PolicySetMetadata
	// the original policy received from the datatore, which could be
	// either a Profile or a Policy.
	Policy interface{}
	// Each member of the Policy set is a hns ACLRule computed from the
	// Policy. When this Policy set needs to be applied, this set of
	// rules is what will be sent to hns for enforcement.
	Members set.Set
	// The set of IP set ids which are referenced by this Policy set. We
	// maintain this to make it easier to look up which Policy sets are
	// impacted (in need of recomputation) after a IP set update occurs.
	IpSetIds set.Set
}
