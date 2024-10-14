// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.
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
// limitations under the License.package globalpolicy

package networkpolicy

import (
	"context"
	"fmt"
	"strings"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

type policyStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy returns a new NamespaceScopedStrategy for instances
func NewStrategy(typer runtime.ObjectTyper) policyStrategy {
	return policyStrategy{typer, names.SimpleNameGenerator}
}

func (policyStrategy) NamespaceScoped() bool {
	return true
}

func (policyStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	obj.(*calico.NetworkPolicy).Name = canonicalizePolicyName(obj)
}

func (policyStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	obj.(*calico.NetworkPolicy).Name = canonicalizePolicyName(old)
}

func canonicalizePolicyName(obj runtime.Object) string {
	// Policies without a tier prepended to their name should have the tier prepended.
	// It's possible for a user to send a policy with one of two name formats:
	//
	// - "tier.policy"
	// - "policy"
	//
	// The logic below handles canonicalizing the name to the former.
	tier := "default"
	if oldPolicy, ok := obj.(*calico.NetworkPolicy); ok && oldPolicy.Spec.Tier != "" {
		tier = oldPolicy.Spec.Tier
	}

	policy := obj.(*calico.NetworkPolicy)
	if len(strings.Split(policy.Name, ".")) == 1 {
		// Tier is not included in the name - add it.
		return tier + "." + policy.Name
	}

	// Name already includes the tier.
	return policy.Name
}

func (policyStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
	// return validation.ValidatePolicy(obj.(*calico.Policy))
}

func (policyStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (policyStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (policyStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return []string{}
}

func (policyStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return []string{}
}

func (policyStrategy) Canonicalize(obj runtime.Object) {
}

func (policyStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
	// return validation.ValidatePolicyUpdate(obj.(*calico.Policy), old.(*calico.Policy))
}

func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	policy, ok := obj.(*calico.NetworkPolicy)
	if !ok {
		return nil, nil, fmt.Errorf("given object is not a Policy.")
	}
	return labels.Set(policy.ObjectMeta.Labels), PolicyToSelectableFields(policy), nil
}

// MatchPolicy is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchPolicy(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// PolicyToSelectableFields returns a field set that represents the object.
func PolicyToSelectableFields(obj *calico.NetworkPolicy) fields.Set {
	return fields.Set{
		"metadata.name":      obj.Name,
		"metadata.namespace": obj.Namespace,
		"spec.tier":          obj.Spec.Tier,
	}
}
