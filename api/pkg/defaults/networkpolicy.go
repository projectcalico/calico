// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package defaults

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func defaultNetworkPolicy(p *v3.NetworkPolicy) (bool, error) {
	changed := defaultPolicyTypesField(p.Spec.Ingress, p.Spec.Egress, &p.Spec.Types)
	changed = setTierLabel(p, p.Spec.Tier) || changed
	return changed, nil
}

func defaultGlobalNetworkPolicy(p *v3.GlobalNetworkPolicy) (bool, error) {
	changed := defaultPolicyTypesField(p.Spec.Ingress, p.Spec.Egress, &p.Spec.Types)
	changed = setTierLabel(p, p.Spec.Tier) || changed
	return changed, nil
}

func defaultStagedNetworkPolicy(p *v3.StagedNetworkPolicy) (bool, error) {
	changed := defaultPolicyTypesField(p.Spec.Ingress, p.Spec.Egress, &p.Spec.Types)
	changed = setTierLabel(p, p.Spec.Tier) || changed
	return changed, nil
}

func defaultStagedGlobalNetworkPolicy(p *v3.StagedGlobalNetworkPolicy) (bool, error) {
	changed := defaultPolicyTypesField(p.Spec.Ingress, p.Spec.Egress, &p.Spec.Types)
	changed = setTierLabel(p, p.Spec.Tier) || changed
	return changed, nil
}

func setTierLabel(obj v1.Object, tier string) bool {
	if tier == "" {
		tier = "default"
	}
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	if labels[v3.LabelTier] != tier {
		labels[v3.LabelTier] = tier
		obj.SetLabels(labels)
		return true
	}
	return false
}

func defaultPolicyTypesField(ingressRules, egressRules []v3.Rule, types *[]v3.PolicyType) bool {
	if len(*types) == 0 {
		// Default the Types field according to what inbound and outbound rules are present
		// in the policy.
		if len(egressRules) == 0 {
			// Policy has no egress rules, so apply this policy to ingress only.  (Note:
			// intentionally including the case where the policy also has no ingress
			// rules.)
			*types = []v3.PolicyType{v3.PolicyTypeIngress}
		} else if len(ingressRules) == 0 {
			// Policy has egress rules but no ingress rules, so apply this policy to
			// egress only.
			*types = []v3.PolicyType{v3.PolicyTypeEgress}
		} else {
			// Policy has both ingress and egress rules, so apply this policy to both
			// ingress and egress.
			*types = []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress}
		}
		return true
	}
	return false
}
