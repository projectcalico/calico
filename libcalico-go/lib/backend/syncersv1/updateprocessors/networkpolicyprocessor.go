// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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
)

// Create a new SyncerUpdateProcessor to sync NetworkPolicy data in v1 format for
// consumption by Felix.
func NewNetworkPolicyUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(apiv3.KindNetworkPolicy, convertNetworkPolicyV2ToV1Key, convertNetworkPolicyV2ToV1Value)
}

func convertNetworkPolicyV2ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Name == "" || v3key.Namespace == "" {
		return model.PolicyKey{}, errors.New("Missing Name or Namespace field to create a v1 NetworkPolicy Key")
	}
	return model.PolicyKey{
		Name: v3key.Namespace + "/" + v3key.Name,
	}, nil
}

func convertNetworkPolicyV2ToV1Value(val interface{}) (interface{}, error) {
	v3res, ok := val.(*apiv3.NetworkPolicy)
	if !ok {
		return nil, errors.New("Value is not a valid NetworkPolicy resource value")
	}

	spec := v3res.Spec
	selector := spec.Selector

	if v3res.Namespace != "" {
		nsSelector := fmt.Sprintf("%s == '%s'", apiv3.LabelNamespace, v3res.Namespace)
		if selector == "" {
			selector = nsSelector
		} else {
			selector = fmt.Sprintf("(%s) && %s", selector, nsSelector)
		}
	}

	selector = prefixAndAppendSelector(selector, spec.ServiceAccountSelector, conversion.ServiceAccountLabelPrefix)

	v1value := &model.Policy{
		Namespace:      v3res.Namespace,
		Order:          spec.Order,
		InboundRules:   RulesAPIV2ToBackend(spec.Ingress, v3res.Namespace),
		OutboundRules:  RulesAPIV2ToBackend(spec.Egress, v3res.Namespace),
		Selector:       selector,
		Types:          policyTypesAPIV2ToBackend(spec.Types),
		ApplyOnForward: true,
	}

	return v1value, nil
}

// policyTypesAPIV2ToBackend converts the policy type field value from the API
// value to the equivalent backend value.
func policyTypesAPIV2ToBackend(ptypes []apiv3.PolicyType) []string {
	var v1ptypes []string
	for _, ptype := range ptypes {
		v1ptypes = append(v1ptypes, policyTypeAPIV2ToBackend(ptype))
	}
	return v1ptypes
}

func policyTypeAPIV2ToBackend(ptype apiv3.PolicyType) string {
	return strings.ToLower(string(ptype))
}
