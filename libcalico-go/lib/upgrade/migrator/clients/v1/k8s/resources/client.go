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

package resources

import (
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// K8sResourceClient is the interface to the k8s datastore for CRUD operations
// on an individual resource (one for each of the *model* types supported by
// the K8s backend).
//
// Defining a separate client interface from api.Client allows the k8s-specific
// client to diverge - for example, the List operation also returns additional
// revision information.
type K8sResourceClient interface {
	// Get returns the object identified by the given key as a KVPair with
	// revision information.
	Get(key model.Key) (*model.KVPair, error)

	// List returns a slice of KVPairs matching the input list options.
	// list should be passed one of the model.<Type>ListOptions structs.
	// Non-zero fields in the struct are used as filters.
	List(list model.ListInterface) ([]*model.KVPair, string, error)
}
