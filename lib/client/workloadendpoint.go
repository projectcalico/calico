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

package client

import (
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend/model"
	. "github.com/tigera/libcalico-go/lib/common"
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
	c *Client
}

// newWorkloadEndpoints returns a workloadEndpoints
func newWorkloadEndpoints(c *Client) *workloadEndpoints {
	return &workloadEndpoints{c}
}

// Create creates a new workload endpoint.
func (w *workloadEndpoints) Create(a *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	return a, w.c.create(*a, w)
}

// Create creates a new workload endpoint.
func (w *workloadEndpoints) Update(a *api.WorkloadEndpoint) (*api.WorkloadEndpoint, error) {
	return a, w.c.update(*a, w)
}

// Create creates a new workload endpoint.
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

// List takes a Metadata, and returns the list of workload endpoints that match that Metadata
// (wildcarding missing fields)
func (w *workloadEndpoints) List(metadata api.WorkloadEndpointMetadata) (*api.WorkloadEndpointList, error) {
	l := api.NewWorkloadEndpointList()
	err := w.c.list(metadata, w, l)
	return l, err
}

// Convert a WorkloadEndpointMetadata to a WorkloadEndpointListInterface
func (w *workloadEndpoints) convertMetadataToListInterface(m interface{}) (model.ListInterface, error) {
	hm := m.(api.WorkloadEndpointMetadata)
	l := model.WorkloadEndpointListOptions{
		Hostname:       hm.Hostname,
		OrchestratorID: hm.OrchestratorID,
		WorkloadID:     hm.WorkloadID,
		EndpointID:     hm.Name,
	}
	return l, nil
}

// Convert a WorkloadEndpointMetadata to a WorkloadEndpointKeyInterface
func (w *workloadEndpoints) convertMetadataToKeyInterface(m interface{}) (model.Key, error) {
	hm := m.(api.WorkloadEndpointMetadata)
	k := model.WorkloadEndpointKey{
		Hostname:       hm.Hostname,
		OrchestratorID: hm.OrchestratorID,
		WorkloadID:     hm.WorkloadID,
		EndpointID:     hm.Name,
	}
	return k, nil
}

// Convert an API WorkloadEndpoint structure to a Backend WorkloadEndpoint structure
func (w *workloadEndpoints) convertAPIToKVPair(a interface{}) (*model.KVPair, error) {
	ah := a.(api.WorkloadEndpoint)
	k, err := w.convertMetadataToKeyInterface(ah.Metadata)
	if err != nil {
		return nil, err
	}

	var ipv4Nets []IPNet
	var ipv6Nets []IPNet
	for _, n := range ah.Spec.IPNetworks {
		if n.Version() == 4 {
			ipv4Nets = append(ipv4Nets, n)
		} else {
			ipv6Nets = append(ipv6Nets, n)
		}
	}

	d := model.KVPair{
		Key: k,
		Value: model.WorkloadEndpoint{
			Labels:     ah.Metadata.Labels,
			State:      "active",
			Name:       ah.Spec.InterfaceName,
			Mac:        ah.Spec.MAC,
			ProfileIDs: ah.Spec.Profiles,
			IPv4Nets:   ipv4Nets,
			IPv6Nets:   ipv6Nets,
		},
	}

	return &d, nil
}

// Convert a Backend WorkloadEndpoint structure to an API WorkloadEndpoint structure
func (w *workloadEndpoints) convertKVPairToAPI(d *model.KVPair) (interface{}, error) {
	bh := d.Value.(model.WorkloadEndpoint)
	bk := d.Key.(model.WorkloadEndpointKey)

	n := bh.IPv4Nets
	n = append(n, bh.IPv6Nets...)

	ah := api.NewWorkloadEndpoint()
	ah.Metadata.Hostname = bk.Hostname
	ah.Metadata.OrchestratorID = bk.OrchestratorID
	ah.Metadata.WorkloadID = bk.OrchestratorID
	ah.Metadata.Name = bk.EndpointID
	ah.Metadata.Labels = bh.Labels
	ah.Spec.InterfaceName = bh.Name
	ah.Spec.MAC = bh.Mac
	ah.Spec.Profiles = bh.ProfileIDs
	ah.Spec.IPNetworks = n

	return ah, nil
}
