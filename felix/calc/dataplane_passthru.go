// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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
	"maps"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
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

type nodeData struct {
	IPv4     *net.IPNet
	IPv6     *net.IPNet
	ASNumber *numorstring.ASNumber
	Labels   map[string]string
}

// DataplanePassthru passes through some datamodel updates to the dataplane layer, removing some
// duplicates along the way.  It maps OnUpdate() calls to dedicated method calls for consistency
// with the rest of the dataplane API.
type DataplanePassthru struct {
	ipv6Support bool
	callbacks   passthruCallbacks

	hosts map[string]*nodeData
}

func NewDataplanePassthru(callbacks passthruCallbacks, ipv6Support bool) *DataplanePassthru {
	return &DataplanePassthru{
		ipv6Support: ipv6Support,
		callbacks:   callbacks,
		hosts:       map[string]*nodeData{},
	}
}

func (h *DataplanePassthru) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.HostIPKey{}, h.OnUpdate)
	dispatcher.Register(model.IPPoolKey{}, h.OnUpdate)
	dispatcher.Register(model.WireguardKey{}, h.OnUpdate)
	dispatcher.Register(model.ResourceKey{}, h.OnUpdate)
}

func (h *DataplanePassthru) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.HostIPKey:
		h.processModelHostIP(key, update)
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
			h.processKindNode(key, update)
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

func (h *DataplanePassthru) processModelHostIP(key model.HostIPKey, update api.Update) {
	hostname := key.Hostname
	if update.Value == nil {
		log.WithField("update", update).Debug("Passing-through HostIP deletion")
		delete(h.hosts, hostname)
		h.callbacks.OnHostMetadataRemove(hostname)
	} else {
		ip := update.Value.(*net.IP)
		oldHost := h.hosts[hostname]
		// libcalico-go's IP struct wraps a standard library IP struct.  To
		// compare two IPs, we need to unwrap them and use Equal() since standard
		// library IPs have multiple, equivalent, representations.
		if oldHost != nil && oldHost.IPv4 != nil && ip.Equal(oldHost.IPv4.IP) {
			log.WithField("update", update).Debug("Ignoring duplicate HostIP update")
			return
		}
		log.WithField("update", update).Debug("Passing-through HostIP update")
		h.hosts[hostname].IPv4 = ip.Network()
		h.callbacks.OnHostMetadataUpdate(hostname, ip.Network(), oldHost.IPv6, oldHost.ASNumber.String(), oldHost.Labels)
	}
}

func (h *DataplanePassthru) processKindNode(key model.ResourceKey, update api.Update) {
	// Handle node resource to pass-through HostMetadataV6Update/HostMetadataV6Remove messages
	// with IPv6 node address updates. IPv4 updates are handled above with model.HostIPKey updates.
	log.WithField("update", update).Debug("Passing-through a Node IPv6 address update")
	log.WithField("update", update).Debug("Passing-through a Node update")
	hostname := key.Name
	if update.Value == nil {
		log.WithField("update", update).Debug("Passing-through Node remove")
		delete(h.hosts, hostname)
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
		h.callbacks.OnHostMetadataUpdate(hostname, bgpIp4net, bgpIp6net, asnumber, node.Labels)

		if h.ipv6Support && node.Spec.BGP == nil {
			// BGP is turned off, try to get one from the node resource. This is a
			// similar fallback as for IPv4, see how HostIPKey is generated in
			// libcalico-go/lib/backend/syncersv1/updateprocessors/felixnodeprocessor.go
			var ipnet *net.IPNet
			_, ipnet = cresources.FindNodeAddress(node, libv3.InternalIP, 6)
			if ipnet == nil {
				_, ipnet = cresources.FindNodeAddress(node, libv3.ExternalIP, 6)
			}
			nodeUpdate := nodeData{
				IPv6: ipnet,
			}
			h.processNodeUpdate(hostname, nodeUpdate)
		}
	}
}

func (h DataplanePassthru) processNodeUpdate(hostname string, nodeUpdate nodeData) {
	var newNode nodeData
	oldNode := h.hosts[hostname]
	if oldNode != nil {
		newNode = *oldNode // Do we need to deep copy?
	}

	updateIsNil := nodeUpdate.IPv4 == nil && nodeUpdate.IPv6 == nil &&
		nodeUpdate.ASNumber == nil && len(nodeUpdate.Labels) == 0

	if oldNode == nil && updateIsNil {
		return
	}

	if oldNode != nil && updateIsNil {
		log.WithField("hostname", hostname).Debug("Passing-through Node remove")
		delete(h.hosts, hostname)
		h.callbacks.OnHostMetadataRemove(hostname)
		return
	}

	var nodeChanged bool
	if nodeUpdate.IPv4 != nil && newNode.IPv4 != nil && nodeUpdate.IPv4.String() != newNode.IPv4.String() {
		nodeChanged = true
		newNode.IPv4 = nodeUpdate.IPv4
	}
	if nodeUpdate.IPv6 != nil && newNode.IPv6 != nil && nodeUpdate.IPv6.String() != newNode.IPv6.String() {
		nodeChanged = true
		newNode.IPv6 = nodeUpdate.IPv6
	}
	if nodeUpdate.ASNumber != nil && newNode.ASNumber != nil && nodeUpdate.ASNumber.String() != newNode.ASNumber.String() {
		nodeChanged = true
		newNode.ASNumber = nodeUpdate.ASNumber
	}
	if !maps.Equal(nodeUpdate.Labels, newNode.Labels) {
		nodeChanged = true
		newNode.Labels = nodeUpdate.Labels
	}

	if nodeChanged {
		log.WithField("new node", newNode).Debug("Passing-through Node update")
		h.hosts[hostname] = &newNode
		h.callbacks.OnHostMetadataUpdate(hostname, newNode.IPv4, newNode.IPv6, newNode.ASNumber.String(), newNode.Labels)
	}
}
