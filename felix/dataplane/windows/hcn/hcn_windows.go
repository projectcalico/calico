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

// This package re-exports the HCN API as a struct sot that it can be shimmed and UTs can run on Linux.
package hcn

import realhcn "github.com/Microsoft/hcsshim/hcn"

type API struct{}

type HostComputeNetwork = realhcn.HostComputeNetwork
type RemoteSubnetRoutePolicySetting = realhcn.RemoteSubnetRoutePolicySetting
type PolicyNetworkRequest = realhcn.PolicyNetworkRequest
type NetworkPolicy = realhcn.NetworkPolicy

const (
	RemoteSubnetRoute = realhcn.RemoteSubnetRoute
)

func (_ API) ListNetworks() ([]HostComputeNetwork, error) {
	return realhcn.ListNetworks()
}
