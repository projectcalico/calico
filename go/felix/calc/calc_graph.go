// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/datastructures/ip"
	"github.com/projectcalico/felix/go/datastructures/labels"
	"github.com/projectcalico/felix/go/datastructures/tags"
	"github.com/projectcalico/felix/go/felix/endpoint"
	"github.com/projectcalico/felix/go/felix/store"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/hash"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

type ipSetUpdateCallbacks interface {
	OnIPSetAdded(setID string)
	OnIPAdded(setID string, ip ip.Addr)
	OnIPRemoved(setID string, ip ip.Addr)
	OnIPSetRemoved(setID string)
}

type rulesUpdateCallbacks interface {
	OnPolicyActive(model.PolicyKey, *ParsedRules)
	OnPolicyInactive(model.PolicyKey)
	OnProfileActive(model.ProfileRulesKey, *ParsedRules)
	OnProfileInactive(model.ProfileRulesKey)
}

type endpointCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.Key,
		endpoint interface{},
		filteredTiers []endpoint.TierInfo)
}

type configCallbacks interface {
	OnConfigUpdate(globalConfig, hostConfig map[string]string)
	OnDatastoreNotReady()
}

type hostIPCallbacks interface {
	OnHostIPUpdate(hostname string, ip *net.IP)
	OnHostIPRemove(hostname string)
}

type PipelineCallbacks interface {
	ipSetUpdateCallbacks
	rulesUpdateCallbacks
	endpointCallbacks
	configCallbacks
	hostIPCallbacks
}

func NewCalculationGraph(callbacks PipelineCallbacks, hostname string) (sourceDispatcher *store.Dispatcher) {
	log.Infof("Creating calculation graph, filtered to hostname %v", hostname)
	// The source of the processing graph, this dispatcher will be fed all
	// the updates from the datastore, fanning them out to the registered
	// handlers.
	sourceDispatcher = store.NewDispatcher()

	// Some of the handlers only need to know about local endpoints.
	// Create a second dispatcher which will filter out non-local endpoints.
	localEndpointFilter := &endpointHostnameFilter{hostname: hostname}
	localEndpointDispatcher := store.NewDispatcher()
	sourceDispatcher.Register(model.WorkloadEndpointKey{}, localEndpointDispatcher)
	sourceDispatcher.Register(model.HostEndpointKey{}, localEndpointDispatcher)
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, localEndpointFilter)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, localEndpointFilter)

	// The active rules calculator matches local endpoints against policies
	// and profiles to figure out which policies/profiles are active on this
	// host.
	activeRulesCalc := NewActiveRulesCalculator()
	// It needs the filtered endpoints...
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, activeRulesCalc)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, activeRulesCalc)
	// ...as well as all the policies and profiles.
	sourceDispatcher.Register(model.PolicyKey{}, activeRulesCalc)
	sourceDispatcher.Register(model.ProfileRulesKey{}, activeRulesCalc)
	sourceDispatcher.Register(model.ProfileLabelsKey{}, activeRulesCalc)

	// The rule scanner takes the output from the active rules calculator
	// and scans the individual rules for selectors and tags.  It generates
	// events when a new selector/tag starts/stops being used.
	ruleScanner := NewRuleScanner()
	activeRulesCalc.RuleScanner = ruleScanner
	ruleScanner.RulesUpdateCallbacks = callbacks

	// The active selector index matches the active selectors found by the
	// rule scanner against *all* endpoints.  It emits events when an
	// endpoint starts/stops matching one of the active selectors.  We
	// send the events to the membership calculator, which will extract the
	// ip addresses of the endpoints.  The member calculator handles tags
	// and selectors uniformly but we need to shim the interface because
	// it expects a string ID.
	var memberCalc *MemberCalculator
	activeSelectorIndex := labels.NewInheritIndex(
		func(selId, labelId interface{}) {
			// Match started callback.
			memberCalc.MatchStarted(labelId, selId.(string))
		},
		func(selId, labelId interface{}) {
			// Match stopped callback.
			memberCalc.MatchStopped(labelId, selId.(string))
		},
	)
	ruleScanner.OnSelectorActive = func(sel selector.Selector) {
		log.Infof("Selector %v now active", sel)
		callbacks.OnIPSetAdded(sel.UniqueId())
		activeSelectorIndex.UpdateSelector(sel.UniqueId(), sel)
	}
	ruleScanner.OnSelectorInactive = func(sel selector.Selector) {
		log.Infof("Selector %v now inactive", sel)
		activeSelectorIndex.DeleteSelector(sel.UniqueId())
		callbacks.OnIPSetRemoved(sel.UniqueId())
	}
	sourceDispatcher.Register(model.ProfileLabelsKey{}, activeSelectorIndex)
	sourceDispatcher.Register(model.WorkloadEndpointKey{}, activeSelectorIndex)
	sourceDispatcher.Register(model.HostEndpointKey{}, activeSelectorIndex)

	// The active tag index does the same for tags.  Calculating which
	// endpoints match each tag.
	tagIndex := tags.NewIndex(
		func(key tags.EndpointKey, tagID string) {
			memberCalc.MatchStarted(key, TagIPSetID(tagID))
		},
		func(key tags.EndpointKey, tagID string) {
			memberCalc.MatchStopped(key, TagIPSetID(tagID))
		},
	)

	ruleScanner.OnTagActive = func(tag string) {
		log.Infof("Tag %v now active", tag)
		callbacks.OnIPSetAdded(hash.MakeUniqueID("t", tag))
		tagIndex.SetTagActive(tag)
	}
	ruleScanner.OnTagInactive = func(tag string) {
		log.Infof("Tag %v now inactive", tag)
		tagIndex.SetTagInactive(tag)
		callbacks.OnIPSetRemoved(hash.MakeUniqueID("t", tag))
	}
	sourceDispatcher.Register(model.WorkloadEndpointKey{}, tagIndex)
	sourceDispatcher.Register(model.HostEndpointKey{}, tagIndex)
	sourceDispatcher.Register(model.ProfileTagsKey{}, tagIndex)

	// The member calculator merges the IPs from different endpoints to
	// calculate the actual IPs that should be in each IP set.  It deals
	// with corner cases, such as having the same IP on multiple endpoints.
	memberCalc = NewMemberCalculator()
	// It needs to know about *all* endpoints to do the calculation.
	sourceDispatcher.Register(model.WorkloadEndpointKey{}, memberCalc)
	sourceDispatcher.Register(model.HostEndpointKey{}, memberCalc)
	// Hook it up to the output.
	memberCalc.callbacks = callbacks

	// The endpoint policy resolver marries up the active policies with
	// local endpoints and calculates the complete, ordered set of
	// policies that apply to each endpoint.
	polResolver := endpoint.NewPolicyResolver()
	// Hook up the inputs to the policy resolver.
	activeRulesCalc.PolicyMatchListener = polResolver
	sourceDispatcher.Register(model.PolicyKey{}, polResolver)
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, polResolver)
	localEndpointDispatcher.Register(model.HostEndpointKey{}, polResolver)
	// And hook its output to the callbacks.
	polResolver.Callbacks = callbacks

	// Register for host IP updates.
	hostIPPassthru := NewHostIPPassthru(callbacks)
	sourceDispatcher.Register(model.HostIPKey{}, hostIPPassthru)

	// Register for config updates.
	configBatcher := NewConfigBatcher(hostname, callbacks)
	sourceDispatcher.Register(model.GlobalConfigKey{}, configBatcher)
	sourceDispatcher.Register(model.HostConfigKey{}, configBatcher)
	sourceDispatcher.Register(model.ReadyFlagKey{}, configBatcher)

	return sourceDispatcher
}

type HostIPPassthru struct {
	callbacks hostIPCallbacks
}

func NewHostIPPassthru(callbacks hostIPCallbacks) *HostIPPassthru {
	return &HostIPPassthru{callbacks: callbacks}
}

func (h *HostIPPassthru) OnUpdate(update model.KVPair) (filterOut bool) {
	hostname := update.Key.(model.HostIPKey).Hostname
	if update.Value == nil {
		h.callbacks.OnHostIPRemove(hostname)
	} else {
		ip := update.Value.(*net.IP)
		h.callbacks.OnHostIPUpdate(hostname, ip)
	}
	return false
}

func (f *HostIPPassthru) OnDatamodelStatus(status api.SyncStatus) {
}

func TagIPSetID(tagID string) string {
	return hash.MakeUniqueID("t", tagID)
}

// endpointHostnameFilter provides an UpdateHandler that filters out endpoints
// that are not on the given host.
type endpointHostnameFilter struct {
	hostname string
}

func (f *endpointHostnameFilter) OnUpdate(update model.KVPair) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if key.Hostname != f.hostname {
			filterOut = true
		}
	case model.HostEndpointKey:
		if key.Hostname != f.hostname {
			filterOut = true
		}
	}
	return
}

func (f *endpointHostnameFilter) OnDatamodelStatus(status api.SyncStatus) {
}
