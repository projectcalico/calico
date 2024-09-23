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

package converters

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

type Node struct{}

// convertAPIToKVPair converts an API Node structure to a KVPair containing a
// backend Node and NodeKey.
// This is part of the conversionHelper interface.
func (n Node) APIV1ToBackendV1(a unversioned.Resource) (*model.KVPair, error) {
	an, ok := a.(*apiv1.Node)
	if !ok {
		return nil, fmt.Errorf("Conversion to Node is not possible with %v", a)
	}

	k, err := n.convertMetadataToKey(an.Metadata)
	if err != nil {
		return nil, err
	}

	v := model.Node{}
	if an.Spec.BGP != nil {
		if an.Spec.BGP.IPv4Address == nil && an.Spec.BGP.IPv6Address == nil {
			return nil, fmt.Errorf("Invalid NodeBGPSpec, missing address: %v", an.Spec.BGP)
		}
		if an.Spec.BGP.IPv4Address != nil {
			v.BGPIPv4Addr = &cnet.IP{IP: an.Spec.BGP.IPv4Address.IP}
			v.BGPIPv4Net = an.Spec.BGP.IPv4Address.Network()
		}
		if an.Spec.BGP.IPv6Address != nil {
			v.BGPIPv6Addr = &cnet.IP{IP: an.Spec.BGP.IPv6Address.IP}
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

	kv := &model.KVPair{Key: k, Value: &v}

	log.WithFields(log.Fields{
		"APIV1":  a,
		"KVPair": *kv,
	}).Debug("Converted Node")
	return kv, nil
}

// convertMetadataToKey converts a NodeMetadata to a NodeKey
func (_ Node) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	nm := m.(apiv1.NodeMetadata)
	k := model.NodeKey{
		Hostname: nm.Name,
	}
	return k, nil
}

// convertKVPairToAPI converts a KVPair containing a backend Node and NodeKey
// to an API Node structure.
// The Node.Spec.BGP.IPv4IPIPTunnelAddr field will need to be populated
// still since it comes from another resource.
// This is part of the conversionHelper interface.
func (_ Node) BackendV1ToAPIV3(d *model.KVPair) (Resource, error) {
	bv, ok := d.Value.(*model.Node)
	if !ok {
		return nil, fmt.Errorf("Value is not a valid Node resource: %v", d.Value)
	}

	bk, ok := d.Key.(model.NodeKey)
	if !ok {
		return nil, fmt.Errorf("Key is not a valid NodeKey resource: %v", d.Value)
	}

	apiNode := libapiv3.NewNode()

	apiNode.ObjectMeta.Name = ConvertNodeName(bk.Hostname)

	if bv.BGPIPv4Addr != nil || bv.BGPIPv6Addr != nil {
		apiNode.Spec.BGP = &libapiv3.NodeBGPSpec{
			ASNumber: bv.BGPASNumber,
		}

		// If the backend has an IPv4 address then fill in the IPv4Address
		// field.  If the IP network does not exist assume a full mask.
		if bv.BGPIPv4Addr != nil {
			if bv.BGPIPv4Net != nil {
				// Stored network is normalised, so copy across the
				// IP separately.
				ipAndNet := net.IPNet{IP: bv.BGPIPv4Addr.IP, Mask: bv.BGPIPv4Net.Mask}
				apiNode.Spec.BGP.IPv4Address = ipAndNet.String()
			} else {
				// No network is stored, assume a full masked network.
				apiNode.Spec.BGP.IPv4Address = bv.BGPIPv4Addr.Network().String()
			}
		}

		// If the backend has an IPv6 address then fill in the IPv6Address
		// field.  If the IP network does not exist assume a full mask.
		if bv.BGPIPv6Addr != nil {
			if bv.BGPIPv6Net != nil {
				// Stored network is normalised, so copy across the
				// IP separately.
				ipAndNet := net.IPNet{IP: bv.BGPIPv6Addr.IP, Mask: bv.BGPIPv6Net.Mask}
				apiNode.Spec.BGP.IPv6Address = ipAndNet.String()
			} else {
				// No network is stored, assume a full masked network.
				apiNode.Spec.BGP.IPv6Address = bv.BGPIPv6Addr.Network().String()
			}
		}
	}

	for _, orchref := range bv.OrchRefs {
		apiNode.Spec.OrchRefs = append(apiNode.Spec.OrchRefs, libapiv3.OrchRef{
			NodeName:     orchref.NodeName,
			Orchestrator: orchref.Orchestrator,
		})
	}

	log.WithFields(log.Fields{
		"KVPair": *d,
		"APIV3":  apiNode,
	}).Debug("Converted Node")
	return apiNode, nil
}
