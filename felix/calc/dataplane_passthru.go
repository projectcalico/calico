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
// HostMetadataUpdate is sourced from two streams that may both be live for the
// same host:
//   - HostIPKey (IPv4 only, derived from Node BGP by the syncer): provides a /32 fallback.
//   - Node resource (BGP IPv4/IPv6 + labels + ASN): authoritative when present.
//
// We track each source separately so a delete on one side doesn't clobber data
// from the other side, then recompute and emit the merged view.
type DataplanePassthru struct {
	ipv6Support bool
	callbacks   passthruCallbacks

	// hostIPv4 is the /32 derived from a HostIPKey update, keyed by hostname.
	hostIPv4 map[string]string

	// nodeInfo is the per-host info derived from a Node resource. A non-nil entry
	// means the Node resource currently exists for that host; nil/missing means it
	// has been deleted (or was treated as deleted because its BGP spec was empty).
	nodeInfo map[string]*HostInfo
}

func NewDataplanePassthru(callbacks passthruCallbacks, ipv6Support bool) *DataplanePassthru {
	return &DataplanePassthru{
		ipv6Support: ipv6Support,
		callbacks:   callbacks,
		hostIPv4:    map[string]string{},
		nodeInfo:    map[string]*HostInfo{},
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

// processModelHostIP handles HostIPKey updates. The value is a bare IPv4 address;
// store it as a host CIDR (/32) so the format matches the Node-resource path.
func (h *DataplanePassthru) processModelHostIP(key model.HostIPKey, update api.Update) {
	hostname := key.Hostname
	before := h.merge(hostname)

	if update.Value == nil {
		logrus.WithField("update", update).Debug("Passing-through HostIP deletion")
		delete(h.hostIPv4, hostname)
	} else {
		ip := update.Value.(*net.IP)
		logrus.WithField("update", update).Debug("Passing-through HostIP update")
		h.hostIPv4[hostname] = ip.String() + "/32"
	}
	h.emitTransition(hostname, before)
}

func (h *DataplanePassthru) processKindNode(key model.ResourceKey, update api.Update) {
	hostname := key.Name
	before := h.merge(hostname)

	if update.Value == nil {
		logrus.WithField("update", update).Debug("Passing-through Node remove")
		delete(h.nodeInfo, hostname)
		h.emitTransition(hostname, before)
		return
	}

	node, _ := update.Value.(*internalapi.Node)
	logrus.WithField("update", update).Debug("Passing-through Node update")

	// An explicitly-empty BGP spec (`BGP: &NodeBGPSpec{}`) is treated as if the
	// Node had been deleted from this stream — there is no useful metadata to
	// pass through. A nil BGP, by contrast, leaves the Node entry alive (with
	// empty IPs) since other Node info such as labels may still be relevant.
	bgpSpec := node.Spec.BGP
	if bgpSpec != nil && bgpSpec.IPv4Address == "" && bgpSpec.IPv6Address == "" && bgpSpec.ASNumber == nil {
		delete(h.nodeInfo, hostname)
		h.emitTransition(hostname, before)
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
	} else {
		// node.Spec.BGP is nil
		if h.ipv6Support {
			// BGP is turned off; fall back to the Node's address list for IPv6.
			// Mirrors how HostIPKey is generated for IPv4 in
			// libcalico-go/lib/backend/syncersv1/updateprocessors/felixnodeprocessor.go.
			ipv6, ipnet := cresources.FindNodeAddress(node, internalapi.InternalIP, 6)
			if ipnet == nil {
				ipv6, ipnet = cresources.FindNodeAddress(node, internalapi.ExternalIP, 6)
			}
			if ipnet != nil {
				ipnet.IP = ipv6.IP
				info.ip6Addr = ipnet.String()
			}
		}
	}

	h.nodeInfo[hostname] = info
	h.emitTransition(hostname, before)
}

// emitTransition emits an Update or Remove based on how the merged view changed
// for hostname. before is the merged HostInfo computed before the source maps
// were mutated; the post-mutation view is recomputed here. Caller must invoke
// this after every change so consecutive calls see consistent before/after
// states.
func (h *DataplanePassthru) emitTransition(hostname string, before *HostInfo) {
	after := h.merge(hostname)

	if after == nil {
		if before != nil {
			h.callbacks.OnHostMetadataRemove(hostname)
		}
		return
	}

	if before != nil && before.equals(after) {
		return
	}
	h.callbacks.OnHostMetadataUpdate(hostname, after)
}

// merge returns the HostInfo to publish for hostname, or nil if neither source
// has live data for it. Node data wins over the HostIPKey fallback when both
// are present; the HostIPKey-derived /32 only fills in IPv4 when there is no
// Node-derived value for it.
func (h *DataplanePassthru) merge(hostname string) *HostInfo {
	node := h.nodeInfo[hostname]
	hostIP, hasHostIP := h.hostIPv4[hostname]

	if node == nil && !hasHostIP {
		return nil
	}

	if node != nil {
		merged := *node
		if merged.ip4Addr == "" && hasHostIP {
			merged.ip4Addr = hostIP
		}
		return &merged
	}
	return &HostInfo{ip4Addr: hostIP}
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
