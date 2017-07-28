// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
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
	}
	return
}
