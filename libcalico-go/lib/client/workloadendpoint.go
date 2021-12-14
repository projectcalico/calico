// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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

package client

import (
	"github.com/google/uuid"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/converter"
)

// WorkloadEndpointInterface has methods to work with WorkloadEndpoint resources.
type WorkloadEndpointInterface interface {
	List(api.WorkloadEndpointMetadata) (*api.WorkloadEndpointList, error)
	Get(api.WorkloadEndpointMetadata) (*api.WorkloadEndpoint, error)
	Create(*api.WorkloadEndpoint) (*api.WorkloadEndpoint, error)
	Update(*api.WorkloadEndpoint) (*api.WorkloadEndpoint, error)
	Apply(*api.WorkloadEndpoint) (*api.WorkloadEndpoint, error)
	Delete(api.WorkloadEndpointMetadata) error
}

// workloadEndpoints implements WorkloadEndpointInterface
type workloadEndpoints struct {
	converter.WorkloadEndpointConverter
	c *Client
}

// newWorkloadEndpoints returns a new WorkloadEndpointInterface bound to the supplied client.
func newWorkloadEndpoints(c *Client) WorkloadEndpointInterface {
	return &workloadEndpoints{c: c}
}

// Create creates a new workload endpoint.
func (w *workloadEndpoints) Create(a *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	// Set any defaults.
	w.setCreateDefaults(a)

	return a, w.c.create(*a, w)
}

// Update updates an existing workload endpoint.
func (w *workloadEndpoints) Update(a *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	return a, w.c.update(*a, w)
}

// Apply updates a workload endpoint if it exists, or creates a new workload endpoint if it does not exist.
func (w *workloadEndpoints) Apply(a *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	return a, w.c.apply(*a, w)
}

// Delete deletes an existing workload endpoint.
func (w *workloadEndpoints) Delete(metadata api.WorkloadEndpointMetadata) error {
	return w.c.delete(metadata, w)
}

// Get returns information about a particular workload endpoint.
func (w *workloadEndpoints) Get(metadata api.WorkloadEndpointMetadata) (*api.WorkloadEndpoint, error) {
	if a, err := w.c.get(metadata, w); err != nil {
		return nil, err
	} else {
		return a.(*api.WorkloadEndpoint), nil
	}
}

// List takes a Metadata, and returns a WorkloadEndpointList that contains the list of workload endpoints
// that match the Metadata (wildcarding missing fields).
func (w *workloadEndpoints) List(metadata api.WorkloadEndpointMetadata) (*api.WorkloadEndpointList, error) {
	l := api.NewWorkloadEndpointList()
	err := w.c.list(metadata, w, l)
	return l, err
}

// setCreateDefaults sets any defaults on a newly created object WorkloadEndpoint.
func (w *workloadEndpoints) setCreateDefaults(wep *api.WorkloadEndpoint) {
	if wep.Metadata.Name == "" {
		wep.Metadata.Name = uuid.NewString()
	}
}

// convertMetadataToListInterface converts a WorkloadEndpointMetadata to a WorkloadEndpointListInterface.
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	hm := m.(api.WorkloadEndpointMetadata)
	l := model.WorkloadEndpointListOptions{
		Hostname:       hm.Node,
		OrchestratorID: hm.Orchestrator,
		WorkloadID:     hm.Workload,
		EndpointID:     hm.Name,
	}
	return l, nil
}

// convertMetadataToKey converts a WorkloadEndpointMetadata to a WorkloadEndpointKey
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	return w.ConvertMetadataToKey(m)
}

// convertAPIToKVPair converts an API WorkloadEndpoint structure to a KVPair containing a
// backend WorkloadEndpoint and WorkloadEndpointKey.
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	return w.ConvertAPIToKVPair(a)
}

// convertKVPairToAPI converts a KVPair containing a backend WorkloadEndpoint and WorkloadEndpointKey
// to an API WorkloadEndpoint structure.
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	return w.ConvertKVPairToAPI(d)
}
