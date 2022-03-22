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
	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// DataplanePassthru passes through some datamodel updates to the dataplane layer, removing some
// duplicates along the way.  It maps OnUpdate() calls to dedicated method calls for consistency
// with the rest of the dataplane API.
type DataplanePassthru struct {
	callbacks passthruCallbacks

	hostIPs map[string]*net.IP
}

func NewDataplanePassthru(callbacks passthruCallbacks) *DataplanePassthru {
	return &DataplanePassthru{
		callbacks: callbacks,
		hostIPs:   map[string]*net.IP{},
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
		hostname := key.Hostname
		if update.Value == nil {
			log.WithField("update", update).Debug("Passing-through HostIP deletion")
			delete(h.hostIPs, hostname)
			h.callbacks.OnHostIPRemove(hostname)
		} else {
			ip := update.Value.(*net.IP)
			oldIP := h.hostIPs[hostname]
			// libcalico-go's IP struct wraps a standard library IP struct.  To
			// compare two IPs, we need to unwrap them and use Equal() since standard
			// library IPs have multiple, equivalent, representations.
			if oldIP != nil && ip.IP.Equal(oldIP.IP) {
				log.WithField("update", update).Debug("Ignoring duplicate HostIP update")
				return
			}
			log.WithField("update", update).Debug("Passing-through HostIP update")
			h.hostIPs[hostname] = ip
			h.callbacks.OnHostIPUpdate(hostname, ip)
		}
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
		} else if key.Kind == model.KindK8sService {
			log.WithField("update", update).Debug("Passing through a Service")
			if update.Value == nil {
				h.callbacks.OnServiceRemove(&proto.ServiceRemove{Name: key.Name, Namespace: key.Namespace})
			} else {
				h.callbacks.OnServiceUpdate(k8sServiceToProto(update.Value.(*kapiv1.Service)))
			}
		} else {
			log.WithField("key", key).Debugf("Ignoring v3 resource of kind %s", key.Kind)
		}
	}
	return
}

func k8sServiceToProto(s *kapiv1.Service) *proto.ServiceUpdate {
	return &proto.ServiceUpdate{
		Name:           s.Name,
		Namespace:      s.Namespace,
		Type:           string(s.Spec.Type),
		ClusterIp:      s.Spec.ClusterIP,
		LoadbalancerIp: s.Spec.LoadBalancerIP,
		ExternalIps:    s.Spec.ExternalIPs,
	}
}
