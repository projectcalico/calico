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

package istio

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// EnvoyFilterGV is the GroupVersion for Istio EnvoyFilter resources.
var EnvoyFilterGV = schema.GroupVersion{Group: "networking.istio.io", Version: "v1alpha3"}

// EnvoyFilter is a typed wrapper around Istio's networking.istio.io/v1alpha3
// EnvoyFilter, used to avoid the full istio.io/client-go dependency while
// still letting the operator's component handler treat it as a
// metav1.ObjectMetaAccessor. Only the fields the operator needs to manage are
// represented; the Spec is an opaque map so we do not have to mirror the full
// EnvoyFilter schema.
type EnvoyFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              map[string]interface{} `json:"spec,omitempty"`
}

// DeepCopyObject implements runtime.Object.
func (e *EnvoyFilter) DeepCopyObject() runtime.Object {
	if e == nil {
		return nil
	}
	out := &EnvoyFilter{
		TypeMeta:   e.TypeMeta,
		ObjectMeta: *e.DeepCopy(),
	}
	if e.Spec != nil {
		out.Spec = runtime.DeepCopyJSON(e.Spec)
	}
	return out
}

// EnvoyFilterList is the list form of EnvoyFilter. Controller-runtime's
// caching client requires the List kind to be registered alongside the item
// kind for watches and List calls to work.
type EnvoyFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EnvoyFilter `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (l *EnvoyFilterList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &EnvoyFilterList{
		TypeMeta: l.TypeMeta,
		ListMeta: *l.DeepCopy(),
	}
	if l.Items != nil {
		out.Items = make([]EnvoyFilter, len(l.Items))
		for i := range l.Items {
			l.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
	return out
}

// DeepCopyInto copies the EnvoyFilter fields into the provided destination.
func (e *EnvoyFilter) DeepCopyInto(out *EnvoyFilter) {
	out.TypeMeta = e.TypeMeta
	e.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if e.Spec != nil {
		out.Spec = runtime.DeepCopyJSON(e.Spec)
	}
}

// AddEnvoyFilterToScheme registers the EnvoyFilter type with the given
// runtime.Scheme so the operator's client can create, update, and delete it.
// It is wired into pkg/apis' AddToSchemes alongside the other third-party
// types, so the manager scheme learns the type centrally; it returns error to
// satisfy runtime.SchemeBuilder.
func AddEnvoyFilterToScheme(s *runtime.Scheme) error {
	s.AddKnownTypeWithName(EnvoyFilterGV.WithKind("EnvoyFilter"), &EnvoyFilter{})
	s.AddKnownTypeWithName(EnvoyFilterGV.WithKind("EnvoyFilterList"), &EnvoyFilterList{})
	metav1.AddToGroupVersion(s, EnvoyFilterGV)
	return nil
}
