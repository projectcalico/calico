// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package components

import (
	"fmt"
	"reflect"
	"slices"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	policyv1 "k8s.io/api/policy/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/projectcalico/calico/operator/api/v1"
)

// OverrideTarget names a rendered object and the user overrides for it.
type OverrideTarget struct {
	kind      reflect.Type
	name      string
	overrides any

	after func(obj client.Object)
}

// Target declares that overrides apply to the rendered T with the given name.
func Target[T client.Object](name string, overrides any) OverrideTarget {
	return OverrideTarget{kind: reflect.TypeFor[T](), name: name, overrides: overrides}
}

// After returns t with fn set to run on the object once the overrides are on it,
// for render work that has to see the overridden values. fn runs whether or not
// there are overrides.
func (t OverrideTarget) After(fn func(obj client.Object)) OverrideTarget {
	t.after = fn
	return t
}

// Matches reports whether obj is the object t names.
func (t OverrideTarget) Matches(obj client.Object) bool {
	return reflect.TypeOf(obj) == t.kind && obj.GetName() == t.name
}

// String names the target in test failures and logs.
func (t OverrideTarget) String() string {
	return fmt.Sprintf("%s %s", t.kind, t.name)
}

// ApplyOverrides applies each target's overrides to the object in objs it names,
// then runs its After. A target whose object isn't in objs is skipped.
func ApplyOverrides(objs []client.Object, targets []OverrideTarget) {
	for _, t := range targets {
		i := slices.IndexFunc(objs, t.Matches)
		if i < 0 {
			continue
		}
		if !isNil(t.overrides) {
			applyOverrides(objs[i], t.overrides)
		}
		if t.after != nil {
			t.after(objs[i])
		}
	}
}

func applyOverrides(obj client.Object, overrides any) {
	switch o := obj.(type) {
	case *appsv1.DaemonSet:
		ApplyDaemonSetOverrides(o, overrides)
	case *appsv1.Deployment:
		ApplyDeploymentOverrides(o, overrides)
	case *appsv1.StatefulSet:
		ApplyStatefulSetOverrides(o, overrides)
	case *batchv1.Job:
		ApplyJobOverrides(o, overrides)
	case *policyv1.PodDisruptionBudget:
		pdb, ok := overrides.(*operator.PodDisruptionBudgetOverride)
		if !ok {
			log.Error(nil, "BUG: PodDisruptionBudget overrides of the wrong type", "type", fmt.Sprintf("%T", overrides))
			return
		}
		ApplyPodDisruptionBudgetOverrides(o, pdb)
	case *envoyapi.EnvoyProxy:
		if svc, ok := overrides.(*operator.GatewayService); ok {
			ApplyEnvoyProxyServiceOverrides(o, svc)
			return
		}
		ApplyEnvoyProxyOverrides(o, overrides)
	default:
		log.Error(nil, "BUG: no way to apply overrides to this kind", "kind", fmt.Sprintf("%T", obj))
	}
}

// isNil reports whether overrides is nil or a typed nil pointer, which is how an
// unset override field arrives.
func isNil(overrides any) bool {
	if overrides == nil {
		return true
	}
	v := reflect.ValueOf(overrides)
	return v.Kind() == reflect.Pointer && v.IsNil()
}
