// Copyright (c) 2016-2017,2020-2021 Tigera, Inc. All rights reserved.
//
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

package calc

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
	libv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	cresources "github.com/projectcalico/calico/libcalico-go/lib/resources"
)

// DataplanePassthru passes through some datamodel updates to the dataplane layer, removing some
// duplicates along the way.  It maps OnUpdate() calls to dedicated method calls for consistency
// with the rest of the dataplane API.
type DataplanePassthru struct {
	ipv6Support bool
	callbacks   passthruCallbacks
}

func NewDataplanePassthru(callbacks passthruCallbacks, ipv6Support bool) *DataplanePassthru {
	return &DataplanePassthru{
		ipv6Support: ipv6Support,
		callbacks:   callbacks,
	}
}

func (h *DataplanePassthru) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.IPPoolKey{}, h.OnUpdate)
	dispatcher.Register(model.WireguardKey{}, h.OnUpdate)
	dispatcher.Register(model.ResourceKey{}, h.OnUpdate)
}

func (h *DataplanePassthru) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.IPPoolKey:
		if update.Value == nil {
			log.WithField("update", update).Debug("Passing-through IPPool deletion")
			h.callbacks.OnIPPoolRemove(key)
		} else {
			log.WithField("update", update).Debug("Passing-through IPPool update")
			pool := update.Value.(*model.IPPool)
			h.callbacks.OnIPPoolUpdate(key, pool)
		}
	case model.WireguardKey:
		if update.Value == nil {
			log.WithField("update", update).Debug("Passing-through Wireguard deletion")
			h.callbacks.OnWireguardRemove(key.NodeName)
		} else {
			log.WithField("update", update).Debug("Passing-through Wireguard update")
			wg := update.Value.(*model.Wireguard)
			h.callbacks.OnWireguardUpdate(key.NodeName, wg)
		}
	case model.ResourceKey:
		if key.Kind == v3.KindBGPConfiguration && key.Name == "default" {
			log.WithField("update", update).Debug("Passing through global BGPConfiguration")
			bgpConfig, _ := update.Value.(*v3.BGPConfiguration)
			h.callbacks.OnGlobalBGPConfigUpdate(bgpConfig)
		} else if key.Kind == model.KindKubernetesService {
			log.WithField("update", update).Debug("Passing through a Service")
			if update.Value == nil {
				h.callbacks.OnServiceRemove(&proto.ServiceRemove{Name: key.Name, Namespace: key.Namespace})
			} else {
				h.callbacks.OnServiceUpdate(kubernetesServiceToProto(update.Value.(*kapiv1.Service)))
			}
		} else if key.Kind == libv3.KindNode {
			// Handle node resource to pass-through HostMetadataV4V6Update/HostMetadataV4V6Remove messages
			// with IPv4 and IPv6 node address updates.
			log.WithField("update", update).Debug("Passing-through a Node update")
			hostname := key.Name
			if update.Value == nil {
				log.WithField("update", update).Debug("Passing-through Node remove")
				h.callbacks.OnHostMetadataRemove(hostname)
			} else {
				node, _ := update.Value.(*libv3.Node)
				log.WithField("update", update).Debug("Passing-through Node update")
				bgpIp4net := &net.IPNet{} // required for print in event sequencer
				bgpIp6net := &net.IPNet{} // required for print in event sequencer
				asnumber := ""
				if node.Spec.BGP != nil {
					ip4, ip4net, _ := net.ParseCIDR(node.Spec.BGP.IPv4Address)
					ip6, ip6net, _ := net.ParseCIDR(node.Spec.BGP.IPv6Address)
					if ip4net != nil {
						ip4net.IP = ip4.IP
						bgpIp4net = ip4net
					}
					if ip6net != nil {
						ip6net.IP = ip6.IP
						bgpIp6net = ip6net
					}
					if node.Spec.BGP.ASNumber != nil {
						asnumber = node.Spec.BGP.ASNumber.String()
					}
				}

				// If BGP is turned off, try to get IPv6 from the node resource.
				// This is a similar fallback as for IPv4, see how HostIPKey is generated in
				// libcalico-go/lib/backend/syncersv1/updateprocessors/felixnodeprocessor.go
				if h.ipv6Support && node.Spec.BGP == nil {
					var ip *net.IP
					ip, _ = cresources.FindNodeAddress(node, libv3.InternalIP, 6)
					if ip == nil {
						ip, _ = cresources.FindNodeAddress(node, libv3.ExternalIP, 6)
					}
					if ip != nil {
						bgpIp6net = &net.IPNet{}
						bgpIp6net.IP = ip.IP
					}
				}

				h.callbacks.OnHostMetadataUpdate(hostname, bgpIp4net, bgpIp6net, asnumber, node.Labels)
			}
		} else {
			log.WithField("key", key).Debugf("Ignoring v3 resource of kind %s", key.Kind)
		}
	}
	return
}

func kubernetesServiceToProto(s *kapiv1.Service) *proto.ServiceUpdate {
	up := &proto.ServiceUpdate{
		Name:           s.Name,
		Namespace:      s.Namespace,
		Type:           string(s.Spec.Type),
		ClusterIps:     s.Spec.ClusterIPs,
		LoadbalancerIp: s.Spec.LoadBalancerIP,
		ExternalIps:    s.Spec.ExternalIPs,
	}

	ports := make([]*proto.ServicePort, 0, len(s.Spec.Ports))

	protoGet := func(kp kapiv1.Protocol) string {
		switch kp {
		case kapiv1.ProtocolUDP:
			return "UDP"
		case kapiv1.ProtocolSCTP:
			return "SCTP"
		}

		return "TCP"
	}

	for _, p := range s.Spec.Ports {
		ports = append(ports, &proto.ServicePort{
			Protocol: protoGet(p.Protocol),
			Port:     p.Port,
			NodePort: p.NodePort,
		})
	}

	up.Ports = ports

	return up
}
