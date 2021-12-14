// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// HostEndpointInterface has methods to work with host endpoint resources.
type HostEndpointInterface interface {

	// List enumerates host endpoint resources matching the supplied metadata and
	// wildcarding missing identifiers.
	List(api.HostEndpointMetadata) (*api.HostEndpointList, error)

	// Get returns the host endpoint resource matching the supplied metadata.  The metadata
	// should contain all identifiers to uniquely identify a single resource.  If the
	// resource does not exist, an errors.ErrorResourceNotFound error is returned.
	Get(api.HostEndpointMetadata) (*api.HostEndpoint, error)

	// Create will create a new host endpoint resource.  If the resource already exists,
	// an errors.ErrorResourceAlreadyExists error is returned.
	Create(*api.HostEndpoint) (*api.HostEndpoint, error)

	// Update will update an existing host endpoint resource.  If the resource does not exist,
	// an errors.ErrorResourceDoesNotExist error is returned.
	Update(*api.HostEndpoint) (*api.HostEndpoint, error)

	// Apply with update an existing host endpoint resource, or create a new one if it does
	// not exist.
	Apply(*api.HostEndpoint) (*api.HostEndpoint, error)

	// Delete will delete a host endpoint resource.  The metadata should contain all identifiers
	// to uniquely identify a single resource.  If the resource does not exist, a
	// errors.ErrorResourceDoesNotExist error is returned.
	Delete(api.HostEndpointMetadata) error
}

// hostEndpoints implements HostEndpointInterface
type hostEndpoints struct {
	c *Client
}

// newHostEndpoints returns a HostEndpointInterface bound to the supplied client.
func newHostEndpoints(c *Client) HostEndpointInterface {
	return &hostEndpoints{c}
}

// Create creates a new host endpoint.
func (h *hostEndpoints) Create(a *api.HostEndpoint) (*api.HostEndpoint, error) {
	return a, h.c.create(*a, h)
}

// Update updates an existing host endpoint.
func (h *hostEndpoints) Update(a *api.HostEndpoint) (*api.HostEndpoint, error) {
	return a, h.c.update(*a, h)
}

// Apply updates a host endpoint if it exists, or creates a new host endpoint if it does not exist.
func (h *hostEndpoints) Apply(a *api.HostEndpoint) (*api.HostEndpoint, error) {
	return a, h.c.apply(*a, h)
}

// Delete deletes an existing host endpoint.
func (h *hostEndpoints) Delete(metadata api.HostEndpointMetadata) error {
	return h.c.delete(metadata, h)
}

// Get returns information about a particular host endpoint.
func (h *hostEndpoints) Get(metadata api.HostEndpointMetadata) (*api.HostEndpoint, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.HostEndpoint), nil
	}
}

// List takes a Metadata, and returns a HostEndpointList that contains the list of host endpoints
// that match the Metadata (wildcarding missing fields).
func (h *hostEndpoints) List(metadata api.HostEndpointMetadata) (*api.HostEndpointList, error) {
	l := api.NewHostEndpointList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts a HostEndpointMetadata to a HostEndpointListOptions.
// This is part of the conversionHelper interface.
func (h *hostEndpoints) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	hm := m.(api.HostEndpointMetadata)
	l := model.HostEndpointListOptions{
		Hostname:   hm.Node,
		EndpointID: hm.Name,
	}
	return l, nil
}

// convertMetadataToKey converts a HostEndpointMetadata to a HostEndpointKey
// This is part of the conversionHelper interface.
func (h *hostEndpoints) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	hm := m.(api.HostEndpointMetadata)
	k := model.HostEndpointKey{
		Hostname:   hm.Node,
		EndpointID: hm.Name,
	}
	return k, nil
}

// convertAPIToKVPair converts an API HostEndpoint structure to a KVPair containing a
// backend HostEndpoint and HostEndpointKey.
// This is part of the conversionHelper interface.
func (h *hostEndpoints) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ah := a.(api.HostEndpoint)
	k, err := h.convertMetadataToKey(ah.Metadata)
	if err != nil {
		return nil, err
	}

	var ipv4Addrs []net.IP
	var ipv6Addrs []net.IP
	for _, ip := range ah.Spec.ExpectedIPs {
		if ip.Version() == 4 {
			ipv4Addrs = append(ipv4Addrs, ip)
		} else {
			ipv6Addrs = append(ipv6Addrs, ip)
		}
	}

	var ports []model.EndpointPort
	for _, port := range ah.Spec.Ports {
		ports = append(ports, model.EndpointPort{
			Name:     port.Name,
			Protocol: port.Protocol,
			Port:     port.Port,
		})
	}

	d := model.KVPair{
		Key: k,
		Value: &model.HostEndpoint{
			Labels: ah.Metadata.Labels,

			Name:              ah.Spec.InterfaceName,
			ProfileIDs:        ah.Spec.Profiles,
			ExpectedIPv4Addrs: ipv4Addrs,
			ExpectedIPv6Addrs: ipv6Addrs,
			Ports:             ports,
		},
	}

	return &d, nil
}

// convertKVPairToAPI converts a KVPair containing a backend HostEndpoint and HostEndpointKey
// to an API HostEndpoint structure.
// This is part of the conversionHelper interface.
func (h *hostEndpoints) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	bh := d.Value.(*model.HostEndpoint)
	bk := d.Key.(model.HostEndpointKey)

	ips := bh.ExpectedIPv4Addrs
	ips = append(ips, bh.ExpectedIPv6Addrs...)

	ah := api.NewHostEndpoint()
	ah.Metadata.Node = bk.Hostname
	ah.Metadata.Name = bk.EndpointID
	ah.Metadata.Labels = bh.Labels
	ah.Spec.InterfaceName = bh.Name
	ah.Spec.Profiles = bh.ProfileIDs
	ah.Spec.ExpectedIPs = ips

	var ports []api.EndpointPort
	for _, port := range bh.Ports {
		ports = append(ports, api.EndpointPort{
			Name:     port.Name,
			Protocol: port.Protocol,
			Port:     port.Port,
		})
	}
	ah.Spec.Ports = ports

	return ah, nil
}
