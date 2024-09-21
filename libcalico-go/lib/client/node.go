// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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
	"context"

	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// NodeInterface has methods to work with Node resources.
type NodeInterface interface {
	List(api.NodeMetadata) (*api.NodeList, error)
	Get(api.NodeMetadata) (*api.Node, error)
	Create(*api.Node) (*api.Node, error)
	Update(*api.Node) (*api.Node, error)
	Apply(*api.Node) (*api.Node, error)
	Delete(api.NodeMetadata) error
}

// nodes implements NodeInterface
type nodes struct {
	c *Client
}

// newNodes returns a new NodeInterface bound to the supplied client.
func newNodes(c *Client) NodeInterface {
	return &nodes{c}
}

// Create creates a new node.
func (h *nodes) Create(a *api.Node) (*api.Node, error) {
	// When creating or updating a node, initialize global defaults if they
	// are not yet initialized.
	if err := h.c.EnsureInitialized(); err != nil {
		return nil, err
	}
	return a, h.c.create(*a, h)
}

// Update updates an existing node.
func (h *nodes) Update(a *api.Node) (*api.Node, error) {
	// When creating or updating a node, initialize global defaults if they
	// are not yet initialized.
	if err := h.c.EnsureInitialized(); err != nil {
		return nil, err
	}
	return a, h.c.update(*a, h)
}

// Apply updates a node if it exists, or creates a new node if it does not exist.
func (h *nodes) Apply(a *api.Node) (*api.Node, error) {
	// When creating or updating a node, initialize global defaults if they
	// are not yet initialized.
	if err := h.c.EnsureInitialized(); err != nil {
		return nil, err
	}
	return a, h.c.apply(*a, h)
}

// Delete deletes an existing node.
func (h *nodes) Delete(metadata api.NodeMetadata) error {
	// Make sure all workload endpoint configuration is deleted, and any IPs
	// that were assigned to these endpoints are deleted.  We check that the
	// node name has been specified, otherwise we'd end up listing all
	// endpoints across all nodes, and delete their config.
	if metadata.Name == "" {
		return errors.ErrorInsufficientIdentifiers{Name: "node"}
	}
	log.Debugf("Deleting node: %s", metadata.Name)

	// Remove BGP Node directory
	log.Debug("Removing BGP Node data")
	err := h.RemoveBGPNode(metadata)
	if err != nil {
		log.Debugf("Error removing BGP Node data: %v", err)
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			return err
		}
	}

	// Finally remove the node.
	return h.c.delete(metadata, h)
}

// Get returns information about a particular node.
func (h *nodes) Get(metadata api.NodeMetadata) (*api.Node, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.Node), nil
	}
}

// List takes a Metadata, and returns a NodeList that contains the list of nodes
// that match the Metadata (wildcarding missing fields).
func (h *nodes) List(metadata api.NodeMetadata) (*api.NodeList, error) {
	l := api.NewNodeList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts a NodeMetadata to a NodeListOptions.
// This is part of the conversionHelper interface.
func (h *nodes) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	nm := m.(api.NodeMetadata)
	l := model.NodeListOptions{
		Hostname: nm.Name,
	}
	return l, nil
}

// convertMetadataToKey converts a NodeMetadata to a NodeKey
// This is part of the conversionHelper interface.
func (h *nodes) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	nm := m.(api.NodeMetadata)
	k := model.NodeKey{
		Hostname: nm.Name,
	}
	return k, nil
}

// convertAPIToKVPair converts an API Node structure to a KVPair containing a
// backend Node and NodeKey.
// This is part of the conversionHelper interface.
func (h *nodes) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	an := a.(api.Node)
	k, err := h.convertMetadataToKey(an.Metadata)
	if err != nil {
		return nil, err
	}

	v := model.Node{}
	if an.Spec.BGP != nil {
		if an.Spec.BGP.IPv4Address != nil {
			v.BGPIPv4Addr = &net.IP{IP: an.Spec.BGP.IPv4Address.IP}
			v.BGPIPv4Net = an.Spec.BGP.IPv4Address.Network()
		}
		if an.Spec.BGP.IPv6Address != nil {
			v.BGPIPv6Addr = &net.IP{IP: an.Spec.BGP.IPv6Address.IP}
			v.BGPIPv6Net = an.Spec.BGP.IPv6Address.Network()
		}
		v.BGPASNumber = an.Spec.BGP.ASNumber
	}

	for _, orchRef := range an.Spec.OrchRefs {
		v.OrchRefs = append(v.OrchRefs, model.OrchRef{
			Orchestrator: orchRef.Orchestrator,
			NodeName:     orchRef.NodeName,
		})
	}

	return &model.KVPair{Key: k, Value: &v}, nil
}

// convertKVPairToAPI converts a KVPair containing a backend Node and NodeKey
// to an API Node structure.
// This is part of the conversionHelper interface.
func (h *nodes) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	bv := d.Value.(*model.Node)
	bk := d.Key.(model.NodeKey)

	apiNode := api.NewNode()
	apiNode.Metadata.Name = bk.Hostname

	if bv.BGPIPv4Addr != nil || bv.BGPIPv6Addr != nil {
		apiNode.Spec.BGP = &api.NodeBGPSpec{
			ASNumber: bv.BGPASNumber,
		}

		// If the backend has an IPv4 address then fill in the IPv4Address
		// field.  If the IP network does not exist assume a full mask.
		if bv.BGPIPv4Addr != nil {
			if bv.BGPIPv4Net != nil {
				// Stored network is normalised, so copy across the
				// IP separately.
				apiNode.Spec.BGP.IPv4Address = bv.BGPIPv4Net
				apiNode.Spec.BGP.IPv4Address.IP = bv.BGPIPv4Addr.IP
			} else {
				// No network is stored, assume a full masked network.
				apiNode.Spec.BGP.IPv4Address = bv.BGPIPv4Addr.Network()
			}
		}

		// If the backend has an IPv6 address then fill in the IPv6Address
		// field.  If the IP network does not exist assume a full mask.
		if bv.BGPIPv6Addr != nil {
			if bv.BGPIPv6Net != nil {
				// Stored network is normalised, so copy across the
				// IP separately.
				apiNode.Spec.BGP.IPv6Address = bv.BGPIPv6Net
				apiNode.Spec.BGP.IPv6Address.IP = bv.BGPIPv6Addr.IP
			} else {
				// No network is stored, assume a full masked network.
				apiNode.Spec.BGP.IPv6Address = bv.BGPIPv6Addr.Network()
			}
		}
	}

	for _, orchref := range bv.OrchRefs {
		apiNode.Spec.OrchRefs = append(apiNode.Spec.OrchRefs, api.OrchRef{
			NodeName:     orchref.NodeName,
			Orchestrator: orchref.Orchestrator,
		})
	}

	return apiNode, nil
}

// RemoveBGPNode removes all Node specific data from the datastore.
func (h *nodes) RemoveBGPNode(metadata api.NodeMetadata) error {
	_, err := h.c.Backend.Delete(context.Background(), model.BGPNodeKey{Host: metadata.Name}, metadata.GetObjectMetadata().Revision)
	if err != nil {
		// Return the error unless the resource does not exist.
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			log.Errorf("Error removing BGP Node: %v", err)
			return err
		}
	}
	return nil
}
