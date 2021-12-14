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

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// HostEndpoint implements the Converter interface.
type HostEndpoint struct{}

// APIV1ToBackendV1 converts an APIv1 HostEndpoint structure to a KVPair containing a
// backend HostEndpoint and HostEndpointKey.
// This is part of the converter interface.
func (_ HostEndpoint) APIV1ToBackendV1(a unversioned.Resource) (*model.KVPair, error) {
	ah, ok := a.(*apiv1.HostEndpoint)
	if !ok {
		return nil, fmt.Errorf("value is not a valid v1 HostEndpoint")
	}
	var ipv4Addrs []cnet.IP
	var ipv6Addrs []cnet.IP
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
		Key: model.HostEndpointKey{
			Hostname:   ah.Metadata.Node,
			EndpointID: ah.Metadata.Name,
		},
		Value: &model.HostEndpoint{
			Labels:            ah.Metadata.Labels,
			Name:              ah.Spec.InterfaceName,
			ProfileIDs:        ah.Spec.Profiles,
			ExpectedIPv4Addrs: ipv4Addrs,
			ExpectedIPv6Addrs: ipv6Addrs,
			Ports:             ports,
		},
	}

	log.WithFields(log.Fields{
		"v1HostEndpoint": a,
		"KVPair":         d,
	}).Debug("Converted HostEndpoint to KVPair")

	return &d, nil
}

// BackendV1ToAPIV3 converts a KVPair containing a backend HostEndpoint and HostEndpointKey
// to an APIv3 HostEndpoint structure.
// This is part of the Converter interface.
func (_ HostEndpoint) BackendV1ToAPIV3(d *model.KVPair) (Resource, error) {
	bh, ok := d.Value.(*model.HostEndpoint)
	if !ok {
		return nil, fmt.Errorf("value is not a valid HostEndpoint value")
	}
	bk, ok := d.Key.(model.HostEndpointKey)
	if !ok {
		return nil, fmt.Errorf("key is not a valid HostEndpoint key")
	}

	var ips []string
	for _, ip := range bh.ExpectedIPv4Addrs {
		ips = append(ips, ip.String())
	}
	for _, ip := range bh.ExpectedIPv6Addrs {
		ips = append(ips, ip.String())
	}

	var ports []apiv3.EndpointPort
	for _, port := range bh.Ports {
		ports = append(ports, apiv3.EndpointPort{
			Name:     port.Name,
			Protocol: numorstring.ProtocolV3FromProtocolV1(port.Protocol),
			Port:     port.Port,
		})
	}

	nodeName := ConvertNodeName(bk.Hostname)

	ah := apiv3.NewHostEndpoint()
	ah.Name = convertName(fmt.Sprintf("%s.%s", nodeName, bk.EndpointID))
	ah.Labels = bh.Labels
	ah.Spec = apiv3.HostEndpointSpec{
		Node:          nodeName,
		Ports:         ports,
		InterfaceName: bh.Name,
		Profiles:      convertProfiles(bh.ProfileIDs),
		ExpectedIPs:   ips,
	}

	log.WithFields(log.Fields{
		"KVPair":         d,
		"v3HostEndpoint": ah,
	}).Debug("Converted KVPair to v3 Resource")

	return ah, nil
}
