// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

const EPCompDataKindIstio = EndpointComputedDataKind("Istio")

var istioSelector = fmt.Sprintf("%s%s == '%s' && %s != '%s' || %s == '%s'",
	conversion.NamespaceLabelPrefix,
	v3.LabelIstioDataplaneMode,
	v3.LabelIstioDataplaneModeAmbient,
	v3.LabelIstioDataplaneMode,
	v3.LabelIstioDataplaneModeNone,
	v3.LabelIstioDataplaneMode,
	v3.LabelIstioDataplaneModeAmbient,
)

// IstioCalculator tracks local workload endpoints that are part of the Istio service mesh
// in ambient mode and marks them accordingly. It registers a selector with the active rules
// calculator to identify endpoints with Istio ambient dataplane mode labels, and updates
// their computed data to indicate they are Istio ambient endpoints. This information is used
// downstream to apply appropriate networking configuration for Istio mesh traffic.
type IstioCalculator struct {
	onEndpointComputedData EndpointComputedDataUpdater
}

func NewIstioCalculator(
	activeRulesCalc *ActiveRulesCalculator,
	ruleScanner *RuleScanner,
	ipSetCallbacks ipSetUpdateCallbacks,
	ipsetMemberIndex *labelindex.SelectorAndNamedPortIndex,
	onEndpointComputedDataUpdater EndpointComputedDataUpdater,
) *IstioCalculator {
	sel, err := selector.Parse(istioSelector)
	if err != nil {
		log.WithError(err).Panicf("Failed to parse selector %q.", istioSelector)
	}

	ic := &IstioCalculator{onEndpointComputedData: onEndpointComputedDataUpdater}
	// Tell the IP set member index to calculate an "all Istio endpoints"
	// IP set.  This will include local and remote endpoints.
	ipSetCallbacks.OnIPSetAdded(rules.IPSetIDAllIstioWEPs, proto.IPSetUpdate_IP)
	ipsetMemberIndex.UpdateIPSet(rules.IPSetIDAllIstioWEPs, sel, ipsetmember.ProtocolNone, "")
	activeRulesCalc.AddExtraComputedSelector(istioSelector)
	// Piggy-back on the active rules calculator's index of local endpoints
	// to give us callbacks when a local endpoint is an Istio endpoint. (The
	// index is expensive so we don't want a second copy here.)
	activeRulesCalc.RegisterPolicyMatchListener(ic)
	return ic
}

func (ic *IstioCalculator) OnPolicyMatch(_ model.PolicyKey, _ model.EndpointKey)        {}
func (ic *IstioCalculator) OnPolicyMatchStopped(_ model.PolicyKey, _ model.EndpointKey) {}

func (ic *IstioCalculator) OnComputedSelectorMatch(cs string, epKey model.EndpointKey) {
	if wepKey, ok := epKey.(model.WorkloadEndpointKey); ok && cs == istioSelector {
		// Always pass a newly created or cloned `computedData` instance to the handler.
		// This ensures the dataplane never receives a mutable object shared elsewhere.
		ic.onEndpointComputedData(wepKey, EPCompDataKindIstio, &ComputedIstioEndpoint{})
	}
}

func (ic *IstioCalculator) OnComputedSelectorMatchStopped(cs string, epKey model.EndpointKey) {
	if wepKey, ok := epKey.(model.WorkloadEndpointKey); ok && cs == istioSelector {
		ic.onEndpointComputedData(wepKey, EPCompDataKindIstio, nil)
	}
}

type ComputedIstioEndpoint struct{}

func (c *ComputedIstioEndpoint) ApplyTo(wep *proto.WorkloadEndpoint) {
	wep.IsIstioAmbient = true
}
