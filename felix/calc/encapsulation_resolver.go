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
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// EncapsulationResolver is a Calculation Graph component that watches IP pool updates and
// calculates if the IPIP or VXLAN encaps should be enabled or disabled. The new Encapsulation
// is sent to the dataplane, which restarts Felix if it changed.
type EncapsulationResolver struct {
	config    *config.Config
	callbacks encapCallbacks
	encapCalc *EncapsulationCalculator
	inSync    bool
}

func NewEncapsulationResolver(config *config.Config, callbacks encapCallbacks) *EncapsulationResolver {
	return &EncapsulationResolver{
		config:    config,
		callbacks: callbacks,
		encapCalc: NewEncapsulationCalculator(config, nil),
		inSync:    false,
	}
}

func (r *EncapsulationResolver) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.IPPoolKey{}, r.OnPoolUpdate)
	dispatcher.RegisterStatusHandler(r.OnStatusUpdate)
}

func (r *EncapsulationResolver) OnPoolUpdate(update api.Update) (filterOut bool) {
	log.WithField("update", update).Debug("EncapsulationResolver: OnPoolUpdate")

	err := r.encapCalc.handlePool(update.KVPair)
	if err != nil {
		log.Infof("error handling update %+v: %v. Ignoring.", update, err)
		return
	}

	r.triggerCalculation()

	return
}

func (r *EncapsulationResolver) OnStatusUpdate(status api.SyncStatus) {
	log.WithField("status", status).Debug("EncapsulationResolver: SyncStatus update")

	if !r.inSync && status == api.InSync {
		r.inSync = true
		r.triggerCalculation()
	}
}

func (r *EncapsulationResolver) triggerCalculation() {
	if !r.inSync {
		// Do nothing if EncapsulationResolver hasn't sync'ed all updates yet
		log.Debug("EncapsulationResolver: skip calculation because inSync is false")
		return
	}

	newEncap := config.Encapsulation{
		IPIPEnabled:  r.encapCalc.IPIPEnabled(),
		VXLANEnabled: r.encapCalc.VXLANEnabled(),
	}

	if r.config.Encapsulation.IPIPEnabled != newEncap.IPIPEnabled || r.config.Encapsulation.VXLANEnabled != newEncap.VXLANEnabled {
		log.WithFields(log.Fields{
			"oldIPIPEnabled":  r.config.Encapsulation.IPIPEnabled,
			"newIPIPEnabled":  newEncap.IPIPEnabled,
			"oldVXLANEnabled": r.config.Encapsulation.VXLANEnabled,
			"newVXLANEnabled": newEncap.VXLANEnabled,
		}).Info("EncapsulationResolver: Encapsulation changed.")
	}

	r.callbacks.OnEncapUpdate(newEncap)
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

func NewEncapsulationCalculator(config *config.Config, ippoolKVPList *model.KVPairList) *EncapsulationCalculator {
	if config == nil {
		log.Panic("Starting EncapsulationResolver with config==nil.")
	}

	encapCalc := &EncapsulationCalculator{
		config:     config,
		ipipPools:  map[string]struct{}{},
		vxlanPools: map[string]struct{}{},
	}

	if ippoolKVPList != nil {
		encapCalc.initPools(ippoolKVPList)
	}

	return encapCalc
}

func (c *EncapsulationCalculator) initPools(ippoolKVPList *model.KVPairList) {
	for _, kvp := range ippoolKVPList.KVPairs {
		err := c.handlePool(*kvp)
		if err != nil {
			log.Infof("error handling update %+v: %v. Ignoring.", *kvp, err)
		}
	}
}

func (c *EncapsulationCalculator) handlePool(p model.KVPair) error {
	if _, ok := p.Key.(model.IPPoolKey); ok {
		// When dealing with an model.IPPool, p.Value is nil for a removal
		return c.handleModelPool(p)
	}

	if _, ok := p.Value.(*apiv3.IPPool); ok {
		// When dealing with an apiv3.IPPool (from listing IP pools via client), p.Key is nil
		return c.handleAPIPool(p)
	}

	return fmt.Errorf("Not a valid IP pool type")
}

func (c *EncapsulationCalculator) handleModelPool(p model.KVPair) error {
	k, ok := p.Key.(model.IPPoolKey)
	if !ok {
		return fmt.Errorf("failed to convert %+v to model.IPPoolKey", p.Key)
	}

	poolKey := k.CIDR.String()
	if p.Value == nil {
		c.removePool(poolKey)
	} else {
		pool, _ := p.Value.(*model.IPPool)
		c.updatePool(poolKey, pool.IPIPMode != encap.Undefined, pool.VXLANMode != encap.Undefined)

	}

	return nil
}

// handleAPIPool handles apiv3.IPPool values in KVPairs. This currently only happens
// in initPools(), which may be passed to NewEncapsulationCalculator() with a list of
// IP pools retrieved from the client.
func (c *EncapsulationCalculator) handleAPIPool(p model.KVPair) error {
	if p.Value == nil {
		// Currently, API pools are only retrieved from an API List() on Felix startup and
		// p.Key is nil in this case.
		// When handling a deletion of an API pool, p.Key will be a model.ResourceKey
		// with Kind apiv3.KindIPPool and a name. A map from IP pool names to CIDRs will
		// be required to handle these.
		return fmt.Errorf("API pool KVPair Value is nil")
	}

	pool, ok := p.Value.(*apiv3.IPPool)
	if !ok {
		return fmt.Errorf("failed to convert %+v to *model.IPPool", p.Value)
	}

	poolKey := pool.Spec.CIDR
	c.updatePool(poolKey, pool.Spec.IPIPMode != apiv3.IPIPModeNever, pool.Spec.VXLANMode != apiv3.VXLANModeNever)

	return nil
}

func (c *EncapsulationCalculator) updatePool(cidr string, ipipEnabled, vxlanEnabled bool) {
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

func (c *EncapsulationCalculator) removePool(cidr string) {
	delete(c.ipipPools, cidr)
	delete(c.vxlanPools, cidr)
}

func (c *EncapsulationCalculator) IPIPEnabled() bool {
	if c.config != nil && c.config.IpInIpEnabled != nil {
		return *c.config.IpInIpEnabled
	}

	return len(c.ipipPools) > 0
}

func (c *EncapsulationCalculator) VXLANEnabled() bool {
	if c.config != nil && c.config.VXLANEnabled != nil {
		return *c.config.VXLANEnabled
	}

	return len(c.vxlanPools) > 0
}
