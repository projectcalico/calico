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
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
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
//
// HostMetadataUpdate is sourced from the v3 Node resource: BGP IPv4/IPv6 plus labels and ASN.
// IPv4 falls back to the Node's address list (Internal preferred, External as backup) whenever
// BGP doesn't supply one — mirroring the old felixnodeprocessor logic that previously fed the
// retired HostIPKey channel. IPv6 falls back to the address list only when BGP is absent.
type DataplanePassthru struct {
	ipv6Support bool
	callbacks   passthruCallbacks

	// nodeInfo is the per-host info derived from a Node resource. A non-nil entry
	// means the Node resource currently exists for that host.
	nodeInfo map[string]*HostInfo
}

func NewDataplanePassthru(callbacks passthruCallbacks, ipv6Support bool) *DataplanePassthru {
	return &DataplanePassthru{
		ipv6Support: ipv6Support,
		callbacks:   callbacks,
		nodeInfo:    map[string]*HostInfo{},
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
			logrus.WithField("update", update).Debug("Passing-through IPPool deletion")
			h.callbacks.OnIPPoolRemove(key)
		} else {
			logrus.WithField("update", update).Debug("Passing-through IPPool update")
			pool := update.Value.(*model.IPPool)
			h.callbacks.OnIPPoolUpdate(key, pool)
		}
	case model.WireguardKey:
		if update.Value == nil {
			logrus.WithField("update", update).Debug("Passing-through Wireguard deletion")
			h.callbacks.OnWireguardRemove(key.NodeName)
		} else {
			logrus.WithField("update", update).Debug("Passing-through Wireguard update")
			wg := update.Value.(*model.Wireguard)
			h.callbacks.OnWireguardUpdate(key.NodeName, wg)
		}
	case model.ResourceKey:
		switch key.Kind {
		case v3.KindBGPConfiguration:
			if key.Name == "default" {
				logrus.WithField("update", update).Debug("Passing through global BGPConfiguration")
				bgpConfig, _ := update.Value.(*v3.BGPConfiguration)
				h.callbacks.OnGlobalBGPConfigUpdate(bgpConfig)
			}
		case model.KindKubernetesService:
			logrus.WithField("update", update).Debug("Passing through a Service")
			if update.Value == nil {
				h.callbacks.OnServiceRemove(&proto.ServiceRemove{Name: key.Name, Namespace: key.Namespace})
			} else {
				h.callbacks.OnServiceUpdate(kubernetesServiceToProto(update.Value.(*kapiv1.Service)))
			}
		case internalapi.KindNode:
			h.processKindNode(key, update)
		default:
			logrus.WithField("key", key).Debugf("Ignoring v3 resource of kind %s", key.Kind)
		}
	}
	return
}

func (h *DataplanePassthru) processKindNode(key model.ResourceKey, update api.Update) {
	hostname := key.Name
	before := h.nodeInfo[hostname]

	if update.Value == nil {
		logrus.WithField("update", update).Debug("Passing-through Node remove")
		delete(h.nodeInfo, hostname)
		if before != nil {
			h.callbacks.OnHostMetadataRemove(hostname)
		}
		return
	}

	node, _ := update.Value.(*internalapi.Node)
	logrus.WithField("update", update).Debug("Passing-through Node update")

	// An explicitly-empty BGP spec (`BGP: &NodeBGPSpec{}`) is treated as if the
	// Node had been deleted — there is no useful metadata to pass through. A nil
	// BGP, by contrast, leaves the Node entry alive (with empty IPs) since other
	// Node info such as labels may still be relevant.
	bgpSpec := node.Spec.BGP
	if bgpSpec != nil && bgpSpec.IPv4Address == "" && bgpSpec.IPv6Address == "" && bgpSpec.ASNumber == nil {
		delete(h.nodeInfo, hostname)
		if before != nil {
			h.callbacks.OnHostMetadataRemove(hostname)
		}
		return
	}

	info := &HostInfo{labels: node.Labels}
	if bgpSpec != nil {
		// BGP IPv4Address/IPv6Address must already be in CIDR form per the v3
		// CRD validation (`cidrv4`/`cidrv6` tags). Bare IPs are dropped silently
		// here so the dataplane never sees an ambiguous address.
		if addr := bgpSpec.IPv4Address; addr != "" {
			if s, ok := parseCIDR(addr); ok {
				info.ip4Addr = s
			} else {
				logrus.WithField("addr", addr).Warn("Ignoring Node BGP IPv4Address: not a CIDR")
			}
		}
		if addr := bgpSpec.IPv6Address; addr != "" {
			if s, ok := parseCIDR(addr); ok {
				info.ip6Addr = s
			} else {
				logrus.WithField("addr", addr).Warn("Ignoring Node BGP IPv6Address: not a CIDR")
			}
		}
		if node.Spec.BGP.ASNumber != nil {
			info.asnumber = node.Spec.BGP.ASNumber.String()
		}
	}
	// If BGP didn't supply an IPv4 address, fall back to the Node's address
	// list. This applies whether BGP is nil or BGP is set without an
	// IPv4Address — matching the legacy felixnodeprocessor behaviour that fed
	// the retired HostIPKey channel.
	if info.ip4Addr == "" {
		ipv4, ipnet := cresources.FindNodeAddress(node, internalapi.InternalIP, 4)
		if ipnet == nil {
			ipv4, ipnet = cresources.FindNodeAddress(node, internalapi.ExternalIP, 4)
		}
		if ipnet != nil {
			ipnet.IP = ipv4.IP
			info.ip4Addr = ipnet.String()
		}
	}
	// IPv6 fallback only fires when BGP is absent, preserving the historical
	// asymmetry: IPv4 had a backup channel (HostIPKey) but IPv6 did not, so
	// the Address list was only consulted for IPv6 when BGP itself was nil.
	if bgpSpec == nil && h.ipv6Support {
		ipv6, ipnet := cresources.FindNodeAddress(node, internalapi.InternalIP, 6)
		if ipnet == nil {
			ipv6, ipnet = cresources.FindNodeAddress(node, internalapi.ExternalIP, 6)
		}
		if ipnet != nil {
			ipnet.IP = ipv6.IP
			info.ip6Addr = ipnet.String()
		}
	}

	h.nodeInfo[hostname] = info
	if before != nil && before.equals(info) {
		return
	}
	h.callbacks.OnHostMetadataUpdate(hostname, info)
}

// parseCIDR strictly parses a CIDR string and returns it normalized to "host
// IP / mask" form (e.g. "192.168.0.2/24" rather than "192.168.0.0/24"). Returns
// false if the string is not a valid CIDR — bare IPs are rejected.
func parseCIDR(s string) (string, bool) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil || ipnet == nil {
		return "", false
	}
	ipnet.IP = ip.IP
	return ipnet.String(), true
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
