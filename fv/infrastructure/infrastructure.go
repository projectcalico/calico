// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

// DatastoreInfra is an interface that is to be used to abstract away
// the datastore being used and the functions that are datastore specific
type DatastoreInfra interface {
	// GetDockerArgs returns a string slice of args to be passed to the docker
	// run command when starting Typha or Felix. It includes
	// CALICO_DATASTORE_TYPE, FELIX_DATASTORETYPE, an appropriate endpoint,
	// and any datastore specific needed ones.
	GetDockerArgs() []string
	// GetBadEndpointDockerArgs returns the same as GetDockerArgs but the
	// endpoint returned will have the incorrect port.
	GetBadEndpointDockerArgs() []string

	// GetCalicoClient will return a client.Interface configured to access
	// the datastore.
	GetCalicoClient() client.Interface
	// SetExpectedIPIPTunnelAddr will set the Felix object's
	// ExpectedIPIPTunnelAddr field, if we expect Felix to see that field being
	// set after it has started up for the first time.
	SetExpectedIPIPTunnelAddr(felix *Felix, idx int, needBGP bool)
	// AddNode will take the appropriate steps to add a node to the datastore.
	// From the passed in felix the Hostname and IPv4 address will be pulled
	// and added to the Node appropriately.
	// The passed in idx will be used to setup the Tunnel or PodCIDR (from
	// which the tunnel is created). needBGP is used (only in etcd) to
	// add a NodeBGPSpec if true or otherwise not.
	AddNode(felix *Felix, idx int, needBGP bool)
	// AddWorkload will take the appropriate steps to create a workload in the
	// datastore with the passed in wep values. If this succeeds then the
	// *api.WorkloadEndpoint will be returned, otherwise an error will be
	// returned.
	AddWorkload(wep *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error)
	// AddDefaultAllow will ensure that the datastore is configured so that
	// the default profile/namespace will allow traffic.
	AddDefaultAllow() error
	// AddDefaultDeny will ensure that the datastore is configured so that
	// the default profile/namespace will deny ingress traffic.
	AddDefaultDeny() error
	// AddAllowToDatastore adds a policy to allow endpoints that match the given
	// selector to reach the datastore.
	AddAllowToDatastore(selector string) error

	// DumpErrorData prints out extra information that may help when an error
	// occurs.
	DumpErrorData()

	// Stop cleans up anything necessary in preparation for the end of the test.
	Stop()
}
