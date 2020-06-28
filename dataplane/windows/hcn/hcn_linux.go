// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

// Dummy version of the HCN API for compilation on Linux.
package hcn

import (
	"encoding/json"
	"reflect"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
)

type API struct{}

type HostComputeNetwork struct {
	// Back pointer back to the original copy of this object.  Since we get returned by
	// slice of structs we need some way to update the original data.
	Ptr *HostComputeNetwork

	Id       string
	Name     string
	Type     NetworkType
	Policies []NetworkPolicy
	Err      error
}

func (network *HostComputeNetwork) RemovePolicy(request PolicyNetworkRequest) error {
	if network.Err != nil {
		return network.Err
	}
	var updatedPols = network.Policies[:0]

outer:
	for _, p := range network.Policies {
		for _, p2 := range request.Policies {
			logrus.Infof("Comparing\n%s\nagainst\n%s", spew.Sdump(p), spew.Sdump(p2))
			if reflect.DeepEqual(p, p2) {
				logrus.Info("Match!")
				continue outer
			}
		}
		updatedPols = append(updatedPols, p)
	}
	network.Ptr.Policies = updatedPols

	return nil
}

func (network *HostComputeNetwork) AddPolicy(request PolicyNetworkRequest) error {
	if network.Err != nil {
		return network.Err
	}
	network.Ptr.Policies = append(network.Ptr.Policies, request.Policies...)
	return nil
}

type NetworkType string

type RemoteSubnetRoutePolicySetting struct {
	DestinationPrefix           string
	IsolationId                 uint16
	ProviderAddress             string
	DistributedRouterMacAddress string
}

type PolicyNetworkRequest struct {
	Policies []NetworkPolicy
}

// NetworkPolicy is a collection of Policy settings for a Network.
type NetworkPolicy struct {
	Type     NetworkPolicyType
	Settings json.RawMessage
}

// NetworkPolicyType are the potential Policies that apply to Networks.
type NetworkPolicyType string

const (
	RemoteSubnetRoute NetworkPolicyType = "RemoteSubnetRoute"
)

func (_ API) ListNetworks() ([]HostComputeNetwork, error) {
	return nil, nil
}
