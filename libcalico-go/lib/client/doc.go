// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

/*
Package client implements the northbound client used to manage Calico configuration.

This client is the main entry point for applications that are managing or querying
Calico configuration.

This client provides a typed interface for managing different resource types.  The
definitions for each resource type are defined in the following package:

	github.com/projectcalico/libcalico-go/lib/api

The client has a number of methods that return interfaces for managing:
  - BGP Peer resources
  - Policy resources
  - IP Pool resources
  - Host endpoint resources
  - Workload endpoint resources
  - Profile resources
  - IP Address Management (IPAM)

See [resource definitions](http://docs.projectcalico.org/latest/reference/calicoctl/resources/) for details about the set of management commands for each
resource type.

The resource management interfaces have a common set of commands to create, delete,
update and retrieve resource instances.  For example, an application using this
client to manage host endpoint resources would create an instance of this client, create a
new HostEndpoints interface and call the appropriate methods on that interface.  For example:

	// NewFromEnv() creates a new client and defaults to access an etcd backend datastore at
	// http://127.0.0.1:2379.  For alternative backend access details, set the appropriate
	// ENV variables specified in the CalicoAPIConfigSpec structure.
	client, err := client.NewFromEnv()

	// Obtain the interface for managing host endpoint resources.
	hostendpoints := client.HostEndpoints()

	// Create a new host endpoint.  All Create() methods return an error of type
	// common.ErrorResourceAlreadyExists if the resource specified by its
	// unique identifiers already exists.
	hostEndpoint, err := hostEndpoints.Create(&api.HostEndpoint{
		Metadata: api.HostEndpointMetadata{
			Name: "endpoint1",
			Nodename: "hostname1",
		},
		Spec: api.HostEndpointSpec{
			InterfaceName: "eth0"
		},
	}

	// Update an existing host endpoint.  All Update() methods return an error of type
	// common.ErrorResourceDoesNotExist if the resource specified by its
	// unique identifiers does not exist.
	hostEndpoint, err = hostEndpoints.Update(&api.HostEndpoint{
		Metadata: api.HostEndpointMetadata{
			Name: "endpoint1",
			Nodename: "hostname1",
		},
		Spec: api.HostEndpointSpec{
			InterfaceName: "eth0",
			Profiles: []string{"profile1"},
		},
	}

	// Apply (update or create) a hostEndpoint.  All Apply() methods will update a resource
	// if it already exists, and will create a new resource if it does not.
	hostEndpoint, err = hostEndpoints.Apply(&api.HostEndpoint{
		Metadata: api.HostEndpointMetadata{
			Name: "endpoint1",
			Nodename: "hostname1",
		},
		Spec: api.HostEndpointSpec{
			InterfaceName: "eth1",
			Profiles: []string{"profile1"},
		},
	}

	// Delete a hostEndpoint.  All Delete() methods return an error of type
	// common.ErrorResourceDoesNotExist if the resource specified by its
	// unique identifiers does not exist.
	hostEndpoint, err = hostEndpoints.Delete(api.HostEndpointMetadata{
		Name: "endpoint1",
		Nodename: "hostname1",
	})

	// Get a hostEndpoint.  All Get() methods return an error of type
	// common.ErrorResourceDoesNotExist if the resource specified by its
	// unique identifiers does not exist.
	hostEndpoint, err = hostEndpoints.Get(api.HostEndpointMetadata{
		Name: "endpoint1",
		Nodename: "hostname1",
	})

	// List all hostEndpoints.  All List() methods take a (sub-)set of the resource
	// identifiers and return the corresponding list resource type that has an
	// Items field containing a list of resources that match the supplied
	// identifiers.
	hostEndpointList, err := hostEndpoints.List(api.HostEndpointMetadata{})
*/
package client
