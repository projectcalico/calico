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

package converter

import (
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// WorkloadEndpointConverter implements a set of functions used for converting between
// API and backend representations of the WorkloadEndpoint resource.
type WorkloadEndpointConverter struct{}

// ConvertMetadataToKey converts a WorkloadEndpointMetadata to a WorkloadEndpointKey
func (w *WorkloadEndpointConverter) ConvertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	hm := m.(api.WorkloadEndpointMetadata)
	k := model.WorkloadEndpointKey{
		Hostname:       hm.Node,
		OrchestratorID: hm.Orchestrator,
		WorkloadID:     hm.Workload,
		EndpointID:     hm.Name,
	}
	return k, nil
}

// ConvertAPIToKVPair converts an API WorkloadEndpoint structure to a KVPair containing a
// backend WorkloadEndpoint and WorkloadEndpointKey.
func (w *WorkloadEndpointConverter) ConvertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ah := a.(api.WorkloadEndpoint)
	k, err := w.ConvertMetadataToKey(ah.Metadata)
	if err != nil {
		return nil, err
	}

	// IP networks are stored in the datastore in separate IPv4 and IPv6
	// fields.  We normalise the network to ensure the IP is correctly
	// masked.
	ipv4Nets := []net.IPNet{}
	ipv6Nets := []net.IPNet{}
	for _, n := range ah.Spec.IPNetworks {
		n = *(n.Network())
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
		Value: &model.WorkloadEndpoint{
			Labels:                     ah.Metadata.Labels,
			ActiveInstanceID:           ah.Metadata.ActiveInstanceID,
			State:                      "active",
			Name:                       ah.Spec.InterfaceName,
			Mac:                        ah.Spec.MAC,
			ProfileIDs:                 ah.Spec.Profiles,
			IPv4Nets:                   ipv4Nets,
			IPv6Nets:                   ipv6Nets,
			IPv4NAT:                    ipv4NAT,
			IPv6NAT:                    ipv6NAT,
			IPv4Gateway:                ah.Spec.IPv4Gateway,
			IPv6Gateway:                ah.Spec.IPv6Gateway,
			Ports:                      ports,
			AllowSpoofedSourcePrefixes: ah.Spec.AllowSpoofedSourcePrefixes,
		},
		Revision: ah.Metadata.Revision,
	}

	return &d, nil
}

// ConvertKVPairToAPI converts a KVPair containing a backend WorkloadEndpoint and WorkloadEndpointKey
// to an API WorkloadEndpoint structure.
func (w *WorkloadEndpointConverter) ConvertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
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

	allowedSources := []net.IPNet{}
	allowedSources = append(allowedSources, bh.AllowSpoofedSourcePrefixes...)

	ah := api.NewWorkloadEndpoint()
	ah.Metadata.Node = bk.Hostname
	ah.Metadata.Orchestrator = bk.OrchestratorID
	ah.Metadata.Workload = bk.WorkloadID
	ah.Metadata.Name = bk.EndpointID
	ah.Metadata.Labels = bh.Labels
	ah.Spec.InterfaceName = bh.Name
	ah.Metadata.ActiveInstanceID = bh.ActiveInstanceID
	ah.Spec.MAC = bh.Mac
	ah.Spec.Profiles = bh.ProfileIDs
	if len(nets) == 0 {
		ah.Spec.IPNetworks = nil
	} else {
		ah.Spec.IPNetworks = nets
	}
	if len(nats) == 0 {
		ah.Spec.IPNATs = nil
	} else {
		ah.Spec.IPNATs = nats
	}
	ah.Spec.IPv4Gateway = bh.IPv4Gateway
	ah.Spec.IPv6Gateway = bh.IPv6Gateway
	ah.Spec.AllowSpoofedSourcePrefixes = allowedSources

	var ports []api.EndpointPort
	for _, port := range bh.Ports {
		ports = append(ports, api.EndpointPort{
			Name:     port.Name,
			Protocol: port.Protocol,
			Port:     port.Port,
		})
	}
	ah.Spec.Ports = ports

	ah.Metadata.Revision = d.Revision

	return ah, nil
}
