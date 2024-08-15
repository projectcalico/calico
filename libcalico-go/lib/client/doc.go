// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.

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
  - Tier resources
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
client to manage tier resources would create an instance of this client, create a
new Tiers interface and call the appropriate methods on that interface.  For example:

	// NewFromEnv() creates a new client and defaults to access an etcd backend datastore at
	// http://127.0.0.1:2379.  For alternative backend access details, set the appropriate
	// ENV variables specified in the CalicoAPIConfigSpec structure.
	clientv3, err := clientv3.NewFromEnv()

	// Obtain the interface for managing tier resources.
	tiers := clientv3.Tiers()

	// Create a new tier.  All Create() methods return an error of type
	// common.ErrorResourceAlreadyExists if the resource specified by its
	// unique identifiers already exists.
	tier, err := tiers.Create(&apiv3.Tier{
		Metadata: apiv3.TierMetadata{
			Name: "tier-1",
		},
		Spec: apiv3.TierSpec{
			Order: 100
		},
	}

	// Update am existing tier.  All Update() methods return an error of type
	// common.ErrorResourceDoesNotExist if the resource specified by its
	// unique identifiers does not exist.
	tier, err = tiers.Update(&apiv3.Tier{
		Metadata: apiv3.TierMetadata{
			Name: "tier-1",
		},
		Spec: apiv3.TierSpec{
			Order: 200
		},
	}

	// Apply (update or create) a tier.  All Apply() methods will update a resource
	// if it already exists, and will create a new resource if it does not.
	tier, err = tiers.Apply(&apiv3.Tier{
		Metadata: apiv3.TierMetadata{
			Name: "tier-2",
		},
		Spec: apiv3.TierSpec{
			Order: 150
		},
	}

	// Delete a tier.  All Delete() methods return an error of type
	// common.ErrorResourceDoesNotExist if the resource specified by its
	// unique identifiers does not exist.
	tier, err = tiers.Delete(apiv3.TierMetadata{
		Name: "tier-2",
	})

	// Get a tier.  All Get() methods return an error of type
	// common.ErrorResourceDoesNotExist if the resource specified by its
	// unique identifiers does not exist.
	tier, err = tiers.Get(apiv3.TierMetadata{
		Name: "tier-2",
	})

	// List all tiers.  All List() methods take a (sub-)set of the resource
	// identifiers and return the corresponding list resource type that has an
	// Items field containing a list of resources that match the supplied
	// identifiers.
	tierList, err := tiers.List(apiv3.TierMetadata{})
*/
package client
