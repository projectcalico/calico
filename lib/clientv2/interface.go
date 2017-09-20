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

package clientv2

import "github.com/projectcalico/libcalico-go/lib/ipam"

type Interface interface {
	// Nodes returns an interface for managing node resources.
	Nodes() NodeInterface
	// GlobalNetworkPolicies returns an interface for managing global network policy resources.
	GlobalNetworkPolicies() GlobalNetworkPolicyInterface
	// NetworkPolicies returns an interface for managing namespaced network policy resources.
	NetworkPolicies(string) NetworkPolicyInterface
	// IPPools returns an interface for managing IP pool resources.
	IPPools() IPPoolInterface
	// Profiles returns an interface for managing profile resources.
	Profiles() ProfileInterface
	// HostEndpoints returns an interface for managing host endpoint resources.
	HostEndpoints() HostEndpointInterface
	// WorkloadEndpoints returns an interface for managing workload endpoint resources.
	WorkloadEndpoints(string) WorkloadEndpointInterface
	// BGPPeers returns an interface for managing BGP peer resources.
	BGPPeers() BGPPeerInterface
	// IPAM returns an interface for managing IP address assignment and releasing.
	IPAM() ipam.Interface
	// EnsureInitialized is used to ensure the backend datastore is correctly
	// initialized for use by Calico.  This method may be called multiple times, and
	// will have no effect if the datastore is already correctly initialized.
	// Most Calico deployment scenarios will automatically implicitly invoke this
	// method and so a general consumer of this API can assume that the datastore
	// is already initialized.
	EnsureInitialized() error
}
