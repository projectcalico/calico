// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	log "github.com/sirupsen/logrus"
)

// PoolEncapManager is a Calculation Graph component that watches IP pool updates and
// calculates if the IPIP or VXLAN encaps should be enabled or disabled. If there is
// a change, Felix restarts to apply them.
type PoolEncapManager struct {
	conf      *config.Config
	callbacks poolEncapCallbacks
	encapInfo *config.EncapInfo
}

func NewPoolEncapManager(callbacks poolEncapCallbacks, conf *config.Config, encapInfo *config.EncapInfo) *PoolEncapManager {
	return &PoolEncapManager{
		conf:      conf,
		callbacks: callbacks,
		encapInfo: encapInfo,
	}
}

func (p *PoolEncapManager) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.IPPoolKey{}, p.OnPoolUpdate)
}

func (p *PoolEncapManager) OnPoolUpdate(update api.Update) (filterOut bool) {
	k := update.Key.(model.IPPoolKey)
	poolKey := k.CIDR.String()

	if update.Value == nil {
		log.WithField("update", update).Debug("Pool Encap Manager: IPPool deletion")
		delete(p.encapInfo.IPIPPools, poolKey)
		delete(p.encapInfo.VXLANPools, poolKey)
	} else {
		log.WithField("update", update).Debug("Pool Encap Manager: IPPool update")
		pool := update.Value.(*model.IPPool)
		if pool.IPIPMode != encap.Undefined {
			p.encapInfo.IPIPPools[poolKey] = struct{}{}
		} else {
			delete(p.encapInfo.IPIPPools, poolKey)
		}
		if pool.VXLANMode != encap.Undefined {
			p.encapInfo.VXLANPools[poolKey] = struct{}{}
		} else {
			delete(p.encapInfo.VXLANPools, poolKey)
		}
	}

	newUseIPIPEncap, newUseVXLANEncap := CalcIPIPVXLANEncaps(p.conf.IpInIpEnabled, p.conf.VXLANEnabled, p.encapInfo.IPIPPools, p.encapInfo.VXLANPools)

	if p.conf != nil && (newUseIPIPEncap != p.encapInfo.UseIPIPEncap || newUseVXLANEncap != p.encapInfo.UseVXLANEncap) {
		log.WithFields(log.Fields{
			"newUseIPIPEncap":  newUseIPIPEncap,
			"newUseVXLANEncap": newUseVXLANEncap,
		}).Info("Pool Encap Manager: UseIPIPEncap and/or UseVXLANEncap changed. Restart Felix.")
		//TODO: panic if ConfigChangedRestartCallback == nil?
		p.encapInfo.ConfigChangedRestartCallback()
	}

	return
}

func CalcIPIPVXLANEncaps(configIPIP, configVXLAN *bool, IPIPPools, VXLANPools map[string]struct{}) (UseIPIPEncap, UseVXLANEncap bool) {
	if configIPIP != nil {
		UseIPIPEncap = *configIPIP
	} else if len(IPIPPools) > 0 {
		UseIPIPEncap = true
	}
	if configVXLAN != nil {
		UseVXLANEncap = *configVXLAN
	} else if len(VXLANPools) > 0 {
		UseVXLANEncap = true
	}
	return
}
