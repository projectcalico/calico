// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"
	"fmt"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// Create a new SyncerUpdateProcessor to sync QoSPolicy data in v1 format for
// consumption by Felix.
func NewQoSPolicyUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(
		apiv3.KindQoSPolicy,
		convertQoSPolicyV3ToV1Key,
		ConvertQoSPolicyV3ToV1Value,
	)
}

func convertQoSPolicyV3ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Name == "" {
		return model.PolicyKey{}, errors.New("Missing Name field to create a v1 QoSPolicy Key")
	}
	return model.PolicyKey{
		Name: fmt.Sprintf("%v.%v", names.QoSPolicyNamePrefix, v3key.Name),
		// QoS policies are not bound to tiers. We just need to set it here for sake of down stream receivers.
		Tier: "default",
	}, nil

}

func ConvertQoSPolicyV3ToV1Value(val interface{}) (interface{}, error) {
	v3res, ok := val.(*apiv3.QoSPolicy)
	if !ok {
		return nil, errors.New("Value is not a valid QoSPolicy resource value")
	}

	spec := v3res.Spec
	selector := spec.Selector

	nsSelector := spec.NamespaceSelector
	if nsSelector != "" {
		selector = prefixAndAppendSelector(selector, nsSelector, conversion.NamespaceLabelPrefix)
		selector = strings.Replace(selector, "all()", "has(projectcalico.org/namespace)", -1)
	}

	v1value := &model.Policy{
		Namespace:     "", // Empty string used to signal a GlobalNetworkPolicy.
		Order:         spec.Order,
		OutboundRules: qosRulesAPIV3ToBackend(spec.Egress),
		Selector:      selector,
		//Types:         policyTypesAPIV3ToBackend(spec.Types), // Is this important?
	}

	return v1value, nil
}

func qosRulesAPIV3ToBackend(rules []apiv3.QoSRule) []model.Rule {
	if len(rules) == 0 {
		return nil
	}
	brs := make([]model.Rule, len(rules))
	for idx, ar := range rules {
		brs[idx] = qosRuleAPIV3ToBackend(ar)
	}
	return brs
}

func qosRuleAPIV3ToBackend(rule apiv3.QoSRule) model.Rule {
	return model.Rule{
		Action:    qosActionAPIV3ToBackend(rule.Action),
		IPVersion: rule.IPVersion,
		Protocol:  convertV3ProtocolToV1(rule.Protocol),
		DstNets:   NormalizeIPNets(rule.Destination.Nets),
		DstPorts:  rule.Destination.Ports,
	}
}

func qosActionAPIV3ToBackend(action apiv3.QoSAction) string {
	if action.DSCP != nil {
		return fmt.Sprintf("dscp:%s", action.DSCP.String())
	}
	return ""
}
