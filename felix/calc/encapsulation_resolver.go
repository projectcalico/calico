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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// EncapsulationResolver is a Calculation Graph component that watches IP pool updates and
// calculates if the IPIP or VXLAN encaps should be enabled or disabled. If there is
// a change, Felix restarts by calling configChangedRestartCallback() to apply them.
type EncapsulationResolver struct {
	config                       *config.Config
	encapCalc                    *EncapsulationCalculator
	configChangedRestartCallback func()
	inSync                       bool
}

func NewEncapsulationResolver(config *config.Config, configChangedRestartCallback func()) *EncapsulationResolver {
	if configChangedRestartCallback == nil {
		log.Panic("Starting EncapsulationResolver with nil callback func.")
	}

	return &EncapsulationResolver{
		config:                       config,
		encapCalc:                    NewEncapsulationCalculator(config, nil),
		configChangedRestartCallback: configChangedRestartCallback,
		inSync:                       false,
	}
}

func (r *EncapsulationResolver) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.IPPoolKey{}, r.OnPoolUpdate)
	dispatcher.RegisterStatusHandler(r.OnStatusUpdate)
}

func (r *EncapsulationResolver) OnPoolUpdate(update api.Update) (filterOut bool) {
	if update.Value == nil {
		log.WithField("update", update).Debug("EncapsulationResolver: IPPool deletion")

		k, ok := update.Key.(model.IPPoolKey)
		if ok {
			r.encapCalc.RemoveModelPool(k)
		} else {
			log.Infof("failed to convert %+v to model.IPPoolKey. Ignoring.", update.Key)
		}
	} else {
		log.WithField("update", update).Debug("EncapsulationResolver: IPPool update")

		pool, ok := update.Value.(*model.IPPool)
		if ok {
			r.encapCalc.UpdateModelPool(pool)
		} else {
			log.Infof("failed to convert %+v to *model.IPPool. Ignoring.", update.Value)
		}
	}

	r.TriggerCalculation()

	return
}

func (r *EncapsulationResolver) OnStatusUpdate(status api.SyncStatus) {
	log.WithField("status", status).Debug("EncapsulationResolver: SyncStatus update")

	if status == api.InSync {
		r.inSync = true
		r.TriggerCalculation()
	}
}

func (r *EncapsulationResolver) TriggerCalculation() {
	// Do nothing if EncapsulationResolver hasn't sync'ed all updates yet
	if !r.inSync {
		return
	}

	if r.config != nil {
		newIPIPEnabled := r.encapCalc.IPIPEnabled()
		newVXLANEnabled := r.encapCalc.VXLANEnabled()

		if r.config.Encapsulation.IPIPEnabled != newIPIPEnabled || r.config.Encapsulation.VXLANEnabled != newVXLANEnabled {
			log.WithFields(log.Fields{
				"oldIPIPEnabled":  r.config.Encapsulation.IPIPEnabled,
				"newIPIPEnabled":  newIPIPEnabled,
				"oldVXLANEnabled": r.config.Encapsulation.VXLANEnabled,
				"newVXLANEnabled": newVXLANEnabled,
			}).Info("EncapsulationResolver: Encapsulation changed. Restart Felix.")
			r.configChangedRestartCallback()
		}
	}
}

// EncapsulationCalculator is a helper struct to aid in calculating if IPIP and/or VXLAN
// encapsulation should be enabled based on the existing IP Pools and their
// configuration. It is used by EncapsulationResolver in this file, where it watches for
// encapsulation changes to restart Felix, and by Run() in daemon.go, where it calculates
// the encapsulation state that will be effectively used by Felix.
type EncapsulationCalculator struct {
	config     *config.Config
	ipipPools  map[string]struct{}
	vxlanPools map[string]struct{}
}

func NewEncapsulationCalculator(config *config.Config, ippoolKVList *model.KVPairList) *EncapsulationCalculator {
	encapCalc := &EncapsulationCalculator{
		config:     config,
		ipipPools:  map[string]struct{}{},
		vxlanPools: map[string]struct{}{},
	}

	if ippoolKVList != nil {
		encapCalc.SetAPIPools(ippoolKVList)
	}

	return encapCalc
}

func (c *EncapsulationCalculator) UpdatePool(cidr string, ipipEnabled, vxlanEnabled bool) {
	if ipipEnabled {
		c.ipipPools[cidr] = struct{}{}
	} else {
		delete(c.ipipPools, cidr)
	}

	if vxlanEnabled {
		c.vxlanPools[cidr] = struct{}{}
	} else {
		delete(c.vxlanPools, cidr)
	}
}

func (c *EncapsulationCalculator) RemovePool(cidr string) {
	delete(c.ipipPools, cidr)
	delete(c.vxlanPools, cidr)
}

func (c *EncapsulationCalculator) UpdateAPIPool(pool *apiv3.IPPool) {
	poolKey := pool.Spec.CIDR
	c.UpdatePool(poolKey, pool.Spec.IPIPMode != apiv3.IPIPModeNever, pool.Spec.VXLANMode != apiv3.VXLANModeNever)
}

func (c *EncapsulationCalculator) SetAPIPools(ippoolKVList *model.KVPairList) {
	for _, kvp := range ippoolKVList.KVPairs {
		pool, ok := kvp.Value.(*apiv3.IPPool)
		if ok {
			c.UpdateAPIPool(pool)
		} else {
			log.Infof("failed to convert %+v to *apiv3.IPPool. Ignoring.", kvp.Value)
		}
	}
}

func (c *EncapsulationCalculator) UpdateModelPool(pool *model.IPPool) {
	poolKey := pool.CIDR.String()
	c.UpdatePool(poolKey, pool.IPIPMode != encap.Undefined, pool.VXLANMode != encap.Undefined)
}

func (c *EncapsulationCalculator) RemoveModelPool(k model.IPPoolKey) {
	poolKey := k.CIDR.String()
	c.RemovePool(poolKey)
}

func (c *EncapsulationCalculator) IPIPEnabled() bool {
	if c.config != nil && c.config.DeprecatedIpInIpEnabled != nil {
		return *c.config.DeprecatedIpInIpEnabled
	}

	if len(c.ipipPools) > 0 {
		return true
	}

	return false
}

func (c *EncapsulationCalculator) VXLANEnabled() bool {
	if c.config != nil && c.config.DeprecatedVXLANEnabled != nil {
		return *c.config.DeprecatedVXLANEnabled
	}

	if len(c.vxlanPools) > 0 {
		return true
	}

	return false
}
