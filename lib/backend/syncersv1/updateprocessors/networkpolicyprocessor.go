// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync NetworkPolicy data in v1 format for
// consumption by Felix.
func NewNetworkPolicyUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(apiv2.KindNetworkPolicy, convertNetworkPolicyV2ToV1Key, convertNetworkPolicyV2ToV1Value)
}

func convertNetworkPolicyV2ToV1Key(v2key model.ResourceKey) (model.Key, error) {
	if v2key.Name == "" || v2key.Namespace == "" {
		return model.PolicyKey{}, errors.New("Missing Name or Namespace field to create a v1 NetworkPolicy Key")
	}
	return model.PolicyKey{
		Name: v2key.Namespace + "/" + v2key.Name,
	}, nil

}

func convertNetworkPolicyV2ToV1Value(val interface{}) (interface{}, error) {
	v2res, ok := val.(*apiv2.NetworkPolicy)
	if !ok {
		return nil, errors.New("Value is not a valid NetworkPolicy resource value")
	}

	// If this policy is namespaced, then add a namespace selector.
	spec := v2res.Spec
	selector := spec.Selector
	if v2res.Namespace != "" {
		nsSelector := fmt.Sprintf("%s == '%s'", apiv2.LabelNamespace, v2res.Namespace)
		if selector == "" {
			selector = nsSelector
		} else {
			selector = fmt.Sprintf("(%s) && %s", selector, nsSelector)
		}
	}

	v1value := &model.Policy{
		Order:          spec.Order,
		InboundRules:   RulesAPIV2ToBackend(spec.IngressRules, v2res.Namespace),
		OutboundRules:  RulesAPIV2ToBackend(spec.EgressRules, v2res.Namespace),
		Selector:       selector,
		Types:          policyTypesAPIV2ToBackend(spec.Types),
		ApplyOnForward: true,
	}

	return v1value, nil
}

// policyTypesAPIV2ToBackend converts the policy type field value from the API
// value to the equivalent backend value.
func policyTypesAPIV2ToBackend(ptypes []apiv2.PolicyType) []string {
	var v1ptypes []string
	for _, ptype := range ptypes {
		v1ptypes = append(v1ptypes, policyTypeAPIV2ToBackend(ptype))
	}
	return v1ptypes
}

func policyTypeAPIV2ToBackend(ptype apiv2.PolicyType) string {
	return strings.ToLower(string(ptype))
}
