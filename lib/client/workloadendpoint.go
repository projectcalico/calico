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
	uuid "github.com/satori/go.uuid"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
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

// newWorkloadEndpoints returns a new WorkloadEndpointInterface bound to the supplied client.
func newWorkloadEndpoints(c *Client) WorkloadEndpointInterface {
	return &workloadEndpoints{c}
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
		wep.Metadata.Name = uuid.NewV4().String()
	}
}

// convertMetadataToListInterface converts a WorkloadEndpointMetadata to a WorkloadEndpointListInterface.
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	hm := m.(api.WorkloadEndpointMetadata)
	l := model.WorkloadEndpointListOptions{
		Hostname:       hm.Hostname,
		OrchestratorID: hm.OrchestratorID,
		WorkloadID:     hm.WorkloadID,
		EndpointID:     hm.Name,
	}
	return l, nil
}

// convertMetadataToKey converts a WorkloadEndpointMetadata to a WorkloadEndpointKey
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	hm := m.(api.WorkloadEndpointMetadata)
	k := model.WorkloadEndpointKey{
		Hostname:       hm.Hostname,
		OrchestratorID: hm.OrchestratorID,
		WorkloadID:     hm.WorkloadID,
		EndpointID:     hm.Name,
	}
	return k, nil
}

// convertAPIToKVPair converts an API WorkloadEndpoint structure to a KVPair containing a
// backend WorkloadEndpoint and WorkloadEndpointKey.
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ah := a.(api.WorkloadEndpoint)
	k, err := w.convertMetadataToKey(ah.Metadata)
	if err != nil {
		return nil, err
	}

	ipv4Nets := []net.IPNet{}
	ipv6Nets := []net.IPNet{}
	for _, n := range ah.Spec.IPNetworks {
		if n.Version() == 4 {
			ipv4Nets = append(ipv4Nets, n)
		} else {
			ipv6Nets = append(ipv6Nets, n)
		}
	}

	ipv4NAT := []model.IPNAT{}
	ipv6NAT := []model.IPNAT{}
	for _, n := range ah.Spec.IPNATs {
		nat := model.IPNAT{IntIP: n.InternalIP, ExtIP: n.ExternalIP}
		if n.InternalIP.Version() == 4 {
			ipv4NAT = append(ipv4NAT, nat)
		} else {
			ipv6NAT = append(ipv6NAT, nat)
		}
	}

	d := model.KVPair{
		Key: k,
		Value: &model.WorkloadEndpoint{
			Labels:      ah.Metadata.Labels,
			State:       "active",
			Name:        ah.Spec.InterfaceName,
			Mac:         ah.Spec.MAC,
			ProfileIDs:  ah.Spec.Profiles,
			IPv4Nets:    ipv4Nets,
			IPv6Nets:    ipv6Nets,
			IPv4NAT:     ipv4NAT,
			IPv6NAT:     ipv6NAT,
			IPv4Gateway: ah.Spec.IPv4Gateway,
			IPv6Gateway: ah.Spec.IPv6Gateway,
		},
	}

	return &d, nil
}

// convertKVPairToAPI converts a KVPair containing a backend WorkloadEndpoint and WorkloadEndpointKey
// to an API WorkloadEndpoint structure.
// This is part of the conversionHelper interface.
func (w *workloadEndpoints) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	bh := d.Value.(*model.WorkloadEndpoint)
	bk := d.Key.(model.WorkloadEndpointKey)

	nets := bh.IPv4Nets
	nets = append(nets, bh.IPv6Nets...)

	nats := []api.IPNAT{}
	mnats := bh.IPv4NAT
	mnats = append(mnats, bh.IPv6NAT...)
	for _, mnat := range mnats {
		nat := api.IPNAT{InternalIP: mnat.IntIP, ExternalIP: mnat.ExtIP}
		nats = append(nats, nat)
	}

	ah := api.NewWorkloadEndpoint()
	ah.Metadata.Hostname = bk.Hostname
	ah.Metadata.OrchestratorID = bk.OrchestratorID
	ah.Metadata.WorkloadID = bk.WorkloadID
	ah.Metadata.Name = bk.EndpointID
	ah.Metadata.Labels = bh.Labels
	ah.Spec.InterfaceName = bh.Name
	ah.Spec.MAC = bh.Mac
	ah.Spec.Profiles = bh.ProfileIDs
	ah.Spec.IPNetworks = nets
	ah.Spec.IPNATs = nats
	ah.Spec.IPv4Gateway = bh.IPv4Gateway
	ah.Spec.IPv6Gateway = bh.IPv6Gateway

	return ah, nil
}
