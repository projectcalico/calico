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
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
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

	hosts map[string]*HostInfo
}

func NewDataplanePassthru(callbacks passthruCallbacks, ipv6Support bool) *DataplanePassthru {
	return &DataplanePassthru{
		ipv6Support: ipv6Support,
		callbacks:   callbacks,
		hosts:       map[string]*HostInfo{},
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
		switch key.Kind {
		case v3.KindBGPConfiguration:
			if key.Name == "default" {
				log.WithField("update", update).Debug("Passing through global BGPConfiguration")
				bgpConfig, _ := update.Value.(*v3.BGPConfiguration)
				h.callbacks.OnGlobalBGPConfigUpdate(bgpConfig)
			}
		case model.KindKubernetesService:
			log.WithField("update", update).Debug("Passing through a Service")
			if update.Value == nil {
				h.callbacks.OnServiceRemove(&proto.ServiceRemove{Name: key.Name, Namespace: key.Namespace})
			} else {
				h.callbacks.OnServiceUpdate(kubernetesServiceToProto(update.Value.(*kapiv1.Service)))
			}
		case internalapi.KindNode:
			h.processKindNode(key, update)
		default:
			log.WithField("key", key).Debugf("Ignoring v3 resource of kind %s", key.Kind)
		}
	}
	return
}

func (h *DataplanePassthru) processModelHostIP(key model.HostIPKey, update api.Update) {
	hostname := key.Hostname
	if update.Value == nil {
		log.WithField("update", update).Debug("Passing-through HostIP deletion")
		delete(h.hosts, hostname)
		h.callbacks.OnHostMetadataRemove(hostname)
		return
	}

	ip := update.Value.(*net.IP)
	log.WithField("update", update).Debug("Passing-through HostIP update")
	hostUpdate := &HostInfo{
		ip4Addr: ip.String(),
		//ip6Addr: "", //TODO remove // required for print in event sequencer
		labels: nil,
	}
	h.processNodeUpdate(hostname, hostUpdate, true)
}

func (h *DataplanePassthru) processKindNode(key model.ResourceKey, update api.Update) {
	// Handle node resource to pass-through HostMetadataV6Update/HostMetadataV6Remove messages
	// with IPv6 node address updates. IPv4 updates are handled above with model.HostIPKey updates.
	log.WithField("update", update).Debug("Passing-through a Node update")
	hostname := key.Name
	if update.Value == nil {
		log.WithField("update", update).Debug("Passing-through Node remove")
		delete(h.hosts, hostname)
		h.callbacks.OnHostMetadataRemove(hostname)
		return
	}

	node, _ := update.Value.(*internalapi.Node)
	log.WithField("update", update).Debug("Passing-through Node update")
	data := &HostInfo{
		//ip4Addr: &net.IPNet{}, // required for print in event sequencer
		//ip6Addr: &net.IPNet{}, // required for print in event sequencer
		labels: node.Labels,
	}

	if node.Spec.BGP != nil {
		logrus.Infof("tofu0 %v", node.Spec.BGP.IPv4Address)
		//ip4, ip4net, _ := net.ParseCIDROrIP(node.Spec.BGP.IPv4Address)
		//ip6, ip6net, _ := net.ParseCIDROrIP(node.Spec.BGP.IPv6Address)
		data.ip4Addr = node.Spec.BGP.IPv4Address
		data.ip6Addr = node.Spec.BGP.IPv6Address
		logrus.Infof("tofu1 %v", data.ip4Addr)
		/* ip4net != nil {
			ip4net.IP = ip4.IP
			data.ip4Addr = ip4net
			logrus.Infof("tofu2 %v", data.ip4Addr)
		}
		if ip6net != nil {
			ip6net.IP = ip6.IP
			data.ip6Addr = ip6net
		}*/
		if node.Spec.BGP.ASNumber != nil {
			data.asnumber = node.Spec.BGP.ASNumber.String()
		}
	}

	if h.ipv6Support && node.Spec.BGP == nil {
		// BGP is turned off, try to get one from the node resource. This is a
		// similar fallback as for IPv4, see how HostIPKey is generated in
		// libcalico-go/lib/backend/syncersv1/updateprocessors/felixnodeprocessor.go
		var ipnet *net.IPNet
		_, ipnet = cresources.FindNodeAddress(node, internalapi.InternalIP, 6)
		if ipnet == nil {
			_, ipnet = cresources.FindNodeAddress(node, internalapi.ExternalIP, 6)
		}
		if ipnet != nil {
			data.ip6Addr = ipnet.String()
		}
	}

	h.processNodeUpdate(hostname, data, false)
}

func (h *DataplanePassthru) processNodeUpdate(hostname string, hostUpdate *HostInfo, fromHostIP bool) {
	updateIsNil := len(hostUpdate.ip4Addr) == 0 && len(hostUpdate.ip6Addr) == 0 &&
		len(hostUpdate.asnumber) == 0 && len(hostUpdate.labels) == 0

	if updateIsNil {
		return
	}

	hostInfo := h.hosts[hostname]
	if hostInfo == nil {
		h.hosts[hostname] = hostUpdate
		h.callbacks.OnHostMetadataUpdate(hostname, hostUpdate)
		return
	}

	// hostInfo in not nil.

	var nodeChanged bool

	if hostUpdate.ip4Addr != hostInfo.ip4Addr {
		logrus.Infof("pepper10 %v", hostUpdate.ip4Addr)
		//if hostUpdate.ip4Addr.IP.String() != hostInfo.ip4Addr.IP.String() {
		// A HostIP-sourced /32 should not overwrite a more specific BGP-sourced prefix
		// (e.g., /24 from a Node resource). Node resource updates always take precedence.
		//if !fromHostIP || !isHostRoute(hostUpdate.ip4Addr) || isHostRoute(hostInfo.ip4Addr) || hostInfo.ip4Addr.IP == nil {
		hostInfo.ip4Addr = hostUpdate.ip4Addr
		nodeChanged = true
		//}
	}

	if hostUpdate.ip6Addr != hostInfo.ip6Addr {
		//if !fromHostIP || !isHostRoute(hostUpdate.ip6Addr) || isHostRoute(hostInfo.ip6Addr) || hostInfo.ip6Addr.IP == nil {
		hostInfo.ip6Addr = hostUpdate.ip6Addr
		nodeChanged = true
		//}
	}

	if hostUpdate.asnumber != hostInfo.asnumber {
		hostInfo.asnumber = hostUpdate.asnumber
		nodeChanged = true
	}

	if !maps.Equal(hostUpdate.labels, hostInfo.labels) {
		hostInfo.labels = hostUpdate.labels
		nodeChanged = true
	}

	if nodeChanged {
		log.WithField("new node", hostInfo).Debug("Passing-through Node update")
		h.hosts[hostname] = hostInfo
		h.callbacks.OnHostMetadataUpdate(hostname, hostInfo)
	}
}

// isHostRoute returns true if the IPNet represents a host route (/32 for IPv4, /128 for IPv6).
// Returns false for empty/nil IPNets.
func isHostRoute(n *net.IPNet) bool {
	if n == nil || n.IP == nil {
		return false
	}
	ones, bits := n.Mask.Size()
	return ones == bits && bits > 0
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
